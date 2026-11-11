local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local config = require("config")
local runtime_cfg = config.runtime or { }
local nft_cfg = config.nft or { }
local auth_cfg = config.auth or { }
local metrics = require("metrics")
local pidfile = require("lib.pidfile")
local metrics_on = (config.metrics or { }).enabled ~= false
local get_l2
get_l2 = require("nfq/ethernet").get_l2
local ip2s, dns_types
do
  local _obj_0 = require("lib.packet_parsing")
  ip2s, dns_types = _obj_0.ip2s, _obj_0.dns_types
end
local skip_ipv6_ext_hdrs, new_dns_tcp_stream, parse_dns_packet
do
  local _obj_0 = require("packet_utils")
  skip_ipv6_ext_hdrs, new_dns_tcp_stream, parse_dns_packet = _obj_0.skip_ipv6_ext_hdrs, _obj_0.new_dns_tcp_stream, _obj_0.parse_dns_packet
end
local encode_ip16
encode_ip16 = require("lib.ipc_hex").encode_ip16
local bit = require("bit")
local filter = require("filter")
local write_msg, write_refused_msg
do
  local _obj_0 = require("ipc")
  write_msg, write_refused_msg = _obj_0.write_msg, _obj_0.write_refused_msg
end
local run_queue, NF_ACCEPT, NF_DROP
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP
end
local log_allow, log_block, log_warn, log_debug, log_info, level_enabled, set_action_prefix
do
  local _obj_0 = require("log")
  log_allow, log_block, log_warn, log_debug, log_info, level_enabled, set_action_prefix = _obj_0.log_allow, _obj_0.log_block, _obj_0.log_warn, _obj_0.log_debug, _obj_0.log_info, _obj_0.level_enabled, _obj_0.set_action_prefix
end
local tsv_field
tsv_field = require("lib.tsv").tsv_field
local user_for_mac
user_for_mac = require("auth.sessions").user_for_mac
local forge_dns = require("forge_dns")
local detect_captive_ips, domain_from_url
do
  local _obj_0 = require("captive_ips")
  detect_captive_ips, domain_from_url = _obj_0.detect, _obj_0.domain_from_url
end
local bridge_raw = require("bridge_raw")
local new_eth, IP4, IP6
do
  local _obj_0 = require("ipparse.l2.ethernet")
  new_eth, IP4, IP6 = _obj_0.new, _obj_0.proto.IP4, _obj_0.proto.IP6
end
local dup_query = require("dup_query")
local raw_send = require("raw_send")
local so_cfg = config.second_opinion or { }
local pipe_wfd = nil
local mac_learn_wfd = nil
local _benchmark_ts = ffi.new("timespec_t[1]")
local CLOCK_MONOTONIC = 1
local get_benchmark_ms
get_benchmark_ms = function()
  if not (runtime_cfg.benchmark) then
    return nil
  end
  libc.clock_gettime(CLOCK_MONOTONIC, _benchmark_ts)
  return tonumber(_benchmark_ts[0].tv_sec) * 1000 + math.floor(tonumber(_benchmark_ts[0].tv_nsec) / 1000000)
end
local events_wfd = nil
local captive_domain = nil
local captive_ip4 = nil
local captive_ip6 = nil
local raw_fd = nil
local _ifindex = nil
local _bridge_mac = nil
local so_enabled = false
local so_resolvers = { }
local so_resolver_set = { }
local so_fds = { }
local arm_resolvers
arm_resolvers = function(resolvers, active)
  for _index_0 = 1, #resolvers do
    local r = resolvers[_index_0]
    so_resolver_set[r] = true
  end
  for fam, ver in pairs({
    ipv4 = 4,
    ipv6 = 6
  }) do
    local _continue_0 = false
    repeat
      if so_fds[fam] then
        _continue_0 = true
        break
      end
      local v_ip = dup_query.pick_resolver(resolvers, ver)
      if v_ip and raw_send.routable(ver, v_ip) then
        local fd = raw_send.open(ver)
        if fd then
          so_fds[fam] = fd
          active[#active + 1] = fam
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
end
local maybe_duplicate
maybe_duplicate = function(ip, l4, raw, rule_resolvers)
  if not (so_enabled and l4.proto == "udp") then
    return 
  end
  local fd = so_fds[ip.version == 6 and "ipv6" or "ipv4"]
  if not (fd) then
    return 
  end
  if so_resolver_set[ip2s(ip.dst)] then
    return 
  end
  local resolvers = rule_resolvers or so_resolvers
  local validator = dup_query.pick_resolver(resolvers, ip.version)
  if not (validator) then
    return 
  end
  local dns_raw = raw:sub(l4.data_off, l4.off + l4.len - 1)
  local pkt = dup_query.build_udp(ip, l4, dns_raw, validator)
  if not (pkt) then
    return 
  end
  return raw_send.send(fd, ip.version, pkt, validator)
end
local write_learn_msg
write_learn_msg = function(ip_raw, mac_raw)
  if not (mac_learn_wfd and mac_learn_wfd >= 0) then
    return false
  end
  if not (mac_raw and #mac_raw == 6) then
    return false
  end
  local ip16 = encode_ip16(ip_raw)
  if not (ip16) then
    return false
  end
  local msg = ffi.new("uint8_t[22]")
  ffi.copy(msg, ip16, 16)
  for i = 1, 6 do
    msg[15 + i] = mac_raw:byte(i)
  end
  local n = libc.write(mac_learn_wfd, msg, 22)
  return n == 22
end
local list_from_condition_reason
list_from_condition_reason = function(condition_reason)
  if not (type(condition_reason) == "string") then
    return nil
  end
  return condition_reason:match("^Domain matched in list '([^']+)'$")
end
local write_event
write_event = function(fields, allowed)
  if not (events_wfd) then
    return 
  end
  local decision
  if allowed then
    decision = "allow"
  else
    decision = "block"
  end
  local line = table.concat({
    tostring(os.time()),
    decision,
    tsv_field(fields.qname),
    tsv_field(fields.mac_src),
    tsv_field(fields.src_ip),
    tsv_field(fields.dst_ip),
    tsv_field(fields.vlan),
    tsv_field(fields.user),
    tsv_field(fields.af),
    tsv_field(fields.reason),
    tsv_field(fields.rule)
  }, "\t") .. "\n"
  return libc.write(events_wfd, line, #line)
end
local tcp_state = new_dns_tcp_stream()
local MAX_RESPONSE_RULE_IDS = 8
local append_unique
append_unique = function(dst, values, limit)
  local overflow = 0
  if not (type(values) == "table") then
    return overflow
  end
  local seen = { }
  for _index_0 = 1, #dst do
    local v = dst[_index_0]
    seen[v] = true
  end
  for _index_0 = 1, #values do
    local _continue_0 = false
    repeat
      local v = values[_index_0]
      if not (v and v ~= "") then
        _continue_0 = true
        break
      end
      if seen[v] then
        _continue_0 = true
        break
      end
      if limit and #dst >= limit then
        overflow = overflow + 1
        _continue_0 = true
        break
      end
      dst[#dst + 1] = v
      seen[v] = true
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return overflow
end
local aggregate_decisions
aggregate_decisions = function(decisions)
  local response_rule_ids = { }
  local allow_modifiers = nil
  local dropped_ids = 0
  for _index_0 = 1, #decisions do
    local _continue_0 = false
    repeat
      local decision = decisions[_index_0]
      if not (decision) then
        _continue_0 = true
        break
      end
      dropped_ids = dropped_ids + append_unique(response_rule_ids, decision.response_rule_ids, MAX_RESPONSE_RULE_IDS)
      if decision.allow_modifiers and next(decision.allow_modifiers) then
        allow_modifiers = allow_modifiers or { }
        for k, v in pairs(decision.allow_modifiers) do
          allow_modifiers[k] = v
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return {
    response_rule_ids = response_rule_ids,
    allow_modifiers = allow_modifiers,
    dropped_ids = dropped_ids
  }
end
local handle_question
handle_question = function(qh_ptr, nfad, pkt_id)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local q_entry_ms = get_benchmark_ms()
  local l2 = get_l2(nfad)
  local ip, l4, dns_msg = parse_dns_packet(raw, tcp_state)
  if not (ip) then
    if l4 == "buffering" then
      return NF_ACCEPT
    end
    if l4 == "tcp_control" then
      return NF_ACCEPT
    end
    log_warn(function()
      return {
        action = "parse_failed",
        mac_src = l2.mac_src,
        status = l4
      }
    end)
    return NF_DROP
  end
  local src_ip = ip2s(ip.src)
  local dst_ip = ip2s(ip.dst)
  if l2.mac_src == "unknown" then
    log_warn(function()
      return {
        action = "l2_mac_missing",
        src_ip = src_ip,
        in_ifindex = l2.in_ifindex,
        vlan = l2.vlan
      }
    end)
  elseif level_enabled and level_enabled("DEBUG") then
    log_debug(function()
      return {
        action = "l2_info",
        mac_src = l2.mac_src,
        src_ip = src_ip,
        in_ifindex = l2.in_ifindex,
        vlan = l2.vlan
      }
    end)
  end
  if dns_msg.header.qr then
    return NF_ACCEPT
  end
  write_learn_msg(ip.src, l2.mac_raw)
  if captive_domain and raw_fd and _bridge_mac then
    for _, q in ipairs(dns_msg.questions) do
      local norm = q.name:lower():gsub("%.+$", "")
      if norm == captive_domain and (q.qtype == 1 or q.qtype == 28) then
        local mac_raw = l2.mac_raw
        if not mac_raw or mac_raw == "\0\0\0\0\0\0" then
          log_warn(function()
            return {
              action = "dns_steal_no_mac",
              domain = q.name,
              src_ip = src_ip
            }
          end)
          break
        end
        local forged_pkts = forge_dns.forge_dns_response(ip, l4, dns_msg.header.id, q, captive_ip4, captive_ip6)
        if forged_pkts then
          local ethertype = ip.version == 6 and IP6 or IP4
          local sent_ok = true
          for _index_0 = 1, #forged_pkts do
            local pkt = forged_pkts[_index_0]
            local eth_bytes = tostring(new_eth({
              src = _bridge_mac,
              dst = mac_raw,
              protocol = ethertype,
              vlan = l2.vlan,
              data = pkt
            }))
            sent_ok = bridge_raw.send(raw_fd, eth_bytes, _ifindex) and sent_ok
          end
          if level_enabled("DEBUG") then
            log_debug(function()
              return {
                action = "dns_stolen",
                domain = q.name,
                qtype = dns_types[q.qtype] or "TYPE" .. tostring(q.qtype),
                proto = l4.proto,
                frames = #forged_pkts,
                src_ip = src_ip,
                resolver = dst_ip,
                mac = l2.mac_src,
                ancount = (captive_ip4 and q.qtype == 1 or captive_ip6 and q.qtype == 28) and 1 or 0,
                sent = sent_ok
              }
            end)
          end
          return NF_DROP
        else
          log_warn(function()
            return {
              action = "dns_steal_forge_failed",
              domain = q.name,
              qtype = dns_types[q.qtype] or "TYPE" .. tostring(q.qtype),
              src_ip = src_ip
            }
          end)
          break
        end
      end
    end
  end
  local verdict = NF_ACCEPT
  local block_reason = nil
  local allow_reason = nil
  local block_rule_id = nil
  local allow_rule_id = nil
  local block_timeout = nil
  local allow_timeout = nil
  local block_modifiers = nil
  local allow_modifiers = nil
  local response_rule_ids = { }
  local decisions = { }
  local q_fields = {
    worker = "dns",
    mac_src = l2.mac_src,
    vlan = l2.vlan,
    in_if = tostring(l2.in_ifindex),
    src_ip = src_ip,
    dst_ip = dst_ip,
    src_port = l4.spt,
    dst_port = l4.dpt,
    txid = string.format("0x%04x", dns_msg.header.id),
    af = ip.version == 6 and "ipv6" or "ipv4",
    user = user_for_mac(l2.mac_src, src_ip, auth_cfg.sessions_file)
  }
  for _, q in ipairs(dns_msg.questions) do
    q_fields.qname = q.name
    q_fields.qtype = dns_types[q.qtype] or "TYPE" .. tostring(q.qtype)
    local req = {
      domain = q.name,
      src_ip = src_ip,
      mac = l2.mac_src,
      vlan = l2.vlan,
      ts = os.time(),
      user = q_fields.user
    }
    local allowed, reason, rule_id, nft_timeout, matched_list = nil, nil, nil, nil, nil
    local decision = filter.decide_meta(req)
    if decision then
      allowed = decision.verdict
      reason = decision.reason
      rule_id = decision.rule_id
      nft_timeout = decision.timeout
      matched_list = list_from_condition_reason(decision.condition_reason)
      decisions[#decisions + 1] = decision
    end
    q_fields.reason = reason or (allowed and "allowed") or "denied"
    q_fields.rule = rule_id or ""
    q_fields.list = matched_list
    if allowed then
      log_allow(function()
        if not (runtime_cfg.benchmark) then
          return q_fields
        end
      end)
      if metrics_on and rule_id then
        metrics.record_verdict(rule_id, "allow")
      end
      allow_reason = reason
      allow_rule_id = rule_id
      allow_timeout = nft_timeout
    else
      log_block(function()
        if not (runtime_cfg.benchmark) then
          return q_fields
        end
      end)
      if metrics_on and rule_id then
        metrics.record_verdict(rule_id, "refuse")
      end
      verdict = NF_DROP
      block_reason = reason
      block_rule_id = rule_id
      block_timeout = nft_timeout
      block_modifiers = decision and decision.modifiers or nil
    end
    write_event(q_fields, allowed)
  end
  local aggregated = aggregate_decisions(decisions)
  response_rule_ids = aggregated.response_rule_ids
  allow_modifiers = aggregated.allow_modifiers
  if aggregated.dropped_ids > 0 then
    log_warn(function()
      return {
        action = "response_rule_ids_truncated",
        dropped = aggregated.dropped_ids,
        max = MAX_RESPONSE_RULE_IDS
      }
    end)
  end
  local q_exit_ms = get_benchmark_ms()
  local question_proc_ms
  if q_entry_ms and q_exit_ms then
    question_proc_ms = q_exit_ms - q_entry_ms
  else
    question_proc_ms = nil
  end
  allow_timeout = allow_timeout or nft_cfg.ip_timeout
  block_timeout = block_timeout or nft_cfg.ip_timeout
  if verdict == NF_ACCEPT then
    q_fields.timeout = allow_timeout
  else
    q_fields.timeout = block_timeout
  end
  local ipc_ok = false
  if verdict == NF_ACCEPT then
    ipc_ok = write_msg(pipe_wfd, dns_msg.header.id, ip.src, l4.spt, l2.mac_raw, ip.dst, allow_reason, q_entry_ms, allow_rule_id, allow_timeout, allow_modifiers, response_rule_ids, question_proc_ms)
  else
    ipc_ok = write_refused_msg(pipe_wfd, dns_msg.header.id, ip.src, l4.spt, l2.mac_raw, ip.dst, block_reason, q_entry_ms, block_rule_id, block_timeout, block_modifiers, response_rule_ids, question_proc_ms)
  end
  if not (ipc_ok) then
    log_warn(function()
      return {
        action = "ipc_write_failed",
        txid = string.format("0x%04x", dns_msg.header.id),
        src_ip = src_ip,
        dst_ip = dst_ip,
        src_port = l4.spt,
        user = q_fields.user
      }
    end)
    return NF_DROP
  end
  local do_duplicate = allow_modifiers and allow_modifiers.validate
  if verdict == NF_ACCEPT and do_duplicate then
    local rule_resolvers = type(do_duplicate) == "table" and do_duplicate or nil
    maybe_duplicate(ip, l4, raw, rule_resolvers)
  end
  return NF_ACCEPT
end
local run
run = function(queue_num, wfd, learn_wfd, ev_wfd, filter_data)
  set_action_prefix("questions_")
  metrics_on = (config.metrics or { }).enabled ~= false
  local runtime_dir = (pidfile.resolve_path(runtime_cfg.pid_file)):match("^(.*)/") or "."
  metrics.init(config.metrics, {
    dir = runtime_dir,
    name = "dns-q" .. tostring(queue_num)
  })
  if metrics_on then
    metrics.write_now()
  end
  pipe_wfd = wfd
  mac_learn_wfd = learn_wfd
  events_wfd = ev_wfd
  if filter_data then
    filter.rules = filter_data.rules
    filter.auth_cfg_cache = filter_data.auth_cfg_cache
    filter.decision_cfg = filter_data.decision_cfg
  end
  do
    local auth = filter.get_auth_cfg()
    captive_domain = domain_from_url(auth.redirect_url)
    captive_ip4, captive_ip6 = detect_captive_ips(auth)
    if captive_domain then
      local ifname = auth.bridge_ifname or "br0"
      local fd, err = bridge_raw.open_socket(ifname)
      if fd then
        raw_fd = fd
        _ifindex = tonumber(ffi.C.if_nametoindex(ifname))
        _bridge_mac = bridge_raw.read_mac(ifname)
        log_info(function()
          return {
            action = "dns_steal_armed",
            domain = captive_domain,
            captive_ip4 = captive_ip4 or "none",
            captive_ip6 = captive_ip6 or "none",
            ifname = ifname
          }
        end)
      else
        log_warn(function()
          return {
            action = "dns_steal_socket_failed",
            err = err,
            ifname = ifname,
            errno = tonumber(ffi.C.__errno_location()[0]) or 0
          }
        end)
      end
    else
      log_info(function()
        return {
          action = "dns_steal_disabled",
          reason = "no hostname in redirect_url"
        }
      end)
    end
    do
      local active = { }
      if #(so_cfg.resolvers or { }) > 0 then
        so_resolvers = so_cfg.resolvers
        arm_resolvers(so_cfg.resolvers, active)
      end
      if filter_data and filter_data.rules then
        local _list_0 = (filter_data.rules.rules_metadata or { })
        for _index_0 = 1, #_list_0 do
          local meta = _list_0[_index_0]
          if meta.validate_resolvers then
            arm_resolvers(meta.validate_resolvers, active)
          end
        end
      end
      so_enabled = #active > 0
      local all_resolvers
      do
        local _accum_0 = { }
        local _len_0 = 1
        for r, _ in pairs(so_resolver_set) do
          _accum_0[_len_0] = r
          _len_0 = _len_0 + 1
        end
        all_resolvers = _accum_0
      end
      if so_enabled then
        log_info(function()
          return {
            action = "dns_validator_armed",
            resolvers = table.concat(all_resolvers, ","),
            families = table.concat(active, ",")
          }
        end)
      elseif #(so_cfg.resolvers or { }) > 0 then
        log_warn(function()
          return {
            action = "dns_validator_disabled",
            reason = "aucun validateur routable"
          }
        end)
      end
    end
  end
  local queue_opts
  if metrics_on then
    queue_opts = {
      idle_ms = 1000,
      on_idle = metrics.flush_if_due
    }
  end
  run_queue(tonumber(queue_num), handle_question, queue_opts)
  if metrics_on then
    return metrics.write_now()
  end
end
return {
  run = run,
  skip_ipv6_ext_hdrs = skip_ipv6_ext_hdrs,
  new_dns_tcp_stream = new_dns_tcp_stream,
  append_unique = append_unique,
  aggregate_decisions = aggregate_decisions,
  MAX_RESPONSE_RULE_IDS = MAX_RESPONSE_RULE_IDS,
  handle_question = handle_question,
  write_event = write_event,
  list_from_condition_reason = list_from_condition_reason
}
