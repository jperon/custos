local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local config = require("config")
local runtime_cfg = config.runtime or { }
local ipc_cfg = config.ipc or { }
local match_retry_cfg = ipc_cfg.match_retry or { }
local dns_cfg = config.dns or { }
local ttl_cfg = dns_cfg.ttl_grace or { }
local auth_cfg = config.auth or { }
local clients_cfg = config.clients or { }
local user_for_mac
user_for_mac = require("auth.sessions").user_for_mac
local parse_ip4, parse_ip6, parse_udp, parse_tcp, parse_dns, ip2s, QTYPE
do
  local _obj_0 = require("lib.packet_parsing")
  parse_ip4, parse_ip6, parse_udp, parse_tcp, parse_dns, ip2s, QTYPE = _obj_0.parse_ip4, _obj_0.parse_ip6, _obj_0.parse_udp, _obj_0.parse_tcp, _obj_0.parse_dns, _obj_0.ip2s, _obj_0.dns_types
end
local skip_ipv6_ext_hdrs, new_dns_tcp_stream
do
  local _obj_0 = require("packet_utils")
  skip_ipv6_ext_hdrs, new_dns_tcp_stream = _obj_0.skip_ipv6_ext_hdrs, _obj_0.new_dns_tcp_stream
end
local get_l2
get_l2 = require("nfq/ethernet").get_l2
local drain_pipe, is_pending, get_pending_entry, consume
do
  local _obj_0 = require("ipc")
  drain_pipe, is_pending, get_pending_entry, consume = _obj_0.drain_pipe, _obj_0.is_pending, _obj_0.get_pending_entry, _obj_0.consume
end
local add_ip4, add_ip6, add_mac4, add_mac6, get_last_seq, wait_ack, drain_ack
do
  local _obj_0 = require("nft_queue")
  add_ip4, add_ip6, add_mac4, add_mac6, get_last_seq, wait_ack, drain_ack = _obj_0.add_ip4, _obj_0.add_ip6, _obj_0.add_mac4, _obj_0.add_mac6, _obj_0.get_last_seq, _obj_0.wait_ack, _obj_0.drain_ack
end
local run_queue, NF_ACCEPT, NF_DROP
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP
end
local log_info, log_warn, log_debug, log_allow, log_block, now, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug, log_allow, log_block, now, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug, _obj_0.log_allow, _obj_0.log_block, _obj_0.now, _obj_0.set_action_prefix
end
local build_blocked_response, build_nxdomain_response, build_sinkhole_response, build_cname_response, strip_https_rr, add_ede_modified, clear_ad_bit, patch_modified_dns
do
  local _obj_0 = require("dns_ede")
  build_blocked_response, build_nxdomain_response, build_sinkhole_response, build_cname_response, strip_https_rr, add_ede_modified, clear_ad_bit, patch_modified_dns = _obj_0.build_blocked_response, _obj_0.build_nxdomain_response, _obj_0.build_sinkhole_response, _obj_0.build_cname_response, _obj_0.strip_https_rr, _obj_0.add_ede_modified, _obj_0.clear_ad_bit, _obj_0.patch_modified_dns
end
local VALIDATOR_REASON = "Filtered by upstream validator"
local rr_timeout, detect_wildcards, inject
do
  local _obj_0 = require("response_inject")
  rr_timeout, detect_wildcards, inject = _obj_0.rr_timeout, _obj_0.detect_wildcards, _obj_0.inject
end
local dns_classify = require("dns_classify")
local second_opinion = require("second_opinion")
local dup_query = require("dup_query")
local raw_send = require("raw_send")
local so_cfg = config.second_opinion or { }
local bit = require("bit")
local retry_cfg = (config.dns or { }).upstream_retry or { }
local retry_enabled = retry_cfg.enabled and true or false
local retry_max = tonumber(retry_cfg.max_attempts) or 2
local retry_rcodes = { }
local _list_0 = (retry_cfg.rcodes or {
  2,
  3,
  5
})
for _index_0 = 1, #_list_0 do
  local rc = _list_0[_index_0]
  retry_rcodes[rc] = true
end
local pending_ttl = ((config.ipc or { }).pending_ttl) or 5
local retry_fds = { }
local RCODE_NXDOMAIN = 3
local ttl_set = require("lib.ttl_set")
local nxdomain_bad = ttl_set.new((retry_cfg.nxdomain_bad_max or 4096), (retry_cfg.nxdomain_bad_ttl or 60), now)
local so_state = nil
local set_verdict
set_verdict = function(qh_ptr, pkt_id, verdict, payload)
  if payload == nil then
    payload = nil
  end
  if payload then
    local ptr = ffi.cast("const unsigned char*", payload)
    return libnfq.nfq_set_verdict(qh_ptr, pkt_id, verdict, #payload, ptr)
  else
    return libnfq.nfq_set_verdict(qh_ptr, pkt_id, verdict, 0, nil)
  end
end
local PROTO_UDP, PROTO_TCP
do
  local _obj_0 = require("lib.checksums")
  PROTO_UDP, PROTO_TCP = _obj_0.PROTO_UDP, _obj_0.PROTO_TCP
end
local tcp_state = new_dns_tcp_stream()
local replace_dns_payload, parse_answers, build_query_from_response
do
  local _obj_0 = require("lib.dns_response")
  replace_dns_payload, parse_answers, build_query_from_response = _obj_0.replace_dns_payload, _obj_0.parse_answers, _obj_0.build_query_from_response
end
local parse_packet
parse_packet = function(raw)
  local ver = bit.rshift(raw:byte(1), 4)
  local ip
  if ver == 4 then
    local ip4, _ = parse_ip4(raw)
    ip = ip4
  elseif ver == 6 then
    local ip6, _ = parse_ip6(raw)
    ip = ip6
  end
  if not (ip) then
    return nil, "parse_failed"
  end
  local l4_off = ip.data_off
  local proto = ip.protocol or ip.next_header
  local ip_ihl = ip.payload_off or (ip.data_off - 1)
  if ip.version == 6 then
    local p = ffi.cast("const uint8_t*", raw)
    local l4_off_0based
    proto, l4_off_0based = skip_ipv6_ext_hdrs(p, #raw, ip.next_header)
    if not (proto) then
      return nil, "parse_failed"
    end
    l4_off = l4_off_0based + 1
    ip_ihl = l4_off_0based
  end
  if proto == PROTO_UDP then
    local udp, _ = parse_udp(raw, l4_off)
    if not (udp) then
      return nil, "parse_failed"
    end
    local dns_raw = raw:sub(udp.data_off, udp.off + udp.len - 1)
    local dns_msg
    dns_msg, _ = parse_dns(dns_raw, 1, false)
    if not (dns_msg) then
      return nil, "parse_failed"
    end
    udp.proto = "udp"
    return ip, udp, dns_msg, dns_raw, ip_ihl
  elseif proto == PROTO_TCP then
    local tcp, _ = parse_tcp(raw, l4_off)
    if not (tcp) then
      return nil, "parse_failed"
    end
    local payload = raw:sub(tcp.data_off)
    local is_fin_rst = bit.band(tcp.flags, 0x05) ~= 0
    local has_payload = payload ~= ""
    local key = tostring(ip.src) .. "|" .. tostring(tcp.spt) .. "|" .. tostring(ip.dst) .. "|" .. tostring(tcp.dpt)
    local buf, init_seq, first_seg = tcp_state.feed(key, payload, tcp.flags, tcp.seq_n)
    if not (buf) then
      return nil, (function()
        if is_fin_rst or not has_payload then
          return "tcp_control"
        else
          return "buffering"
        end
      end)()
    end
    local dns_raw = buf:sub(3)
    local dns_msg
    dns_msg, _ = parse_dns(dns_raw, 1, false)
    if not (dns_msg) then
      return nil, "parse_failed"
    end
    tcp.proto = "tcp"
    tcp.tcp_init_seq = init_seq
    tcp.tcp_single_segment = first_seg
    tcp.tcp_dns_raw = dns_raw
    return ip, tcp, dns_msg, dns_raw, ip_ihl
  end
  return nil, "parse_failed"
end
local _filter = nil
local run_on_response
run_on_response = function(rule_id, dns_raw, reason, ctx_extra)
  if ctx_extra == nil then
    ctx_extra = nil
  end
  _filter = _filter or require("filter")
  return _filter.run_on_response(rule_id, dns_raw, reason, ctx_extra)
end
local rules_metadata = nil
local auth_wildcard_rules = { }
local load_auth_wildcard_rules
load_auth_wildcard_rules = function(metadata)
  rules_metadata = metadata
  auth_wildcard_rules = detect_wildcards(metadata)
  return log_info(function()
    return {
      action = "auth_wildcard_rules_loaded",
      count = #auth_wildcard_rules,
      rules = table.concat(auth_wildcard_rules, ", ")
    }
  end)
end
local IPC_RETRY_ENABLED
if match_retry_cfg.enabled == nil then
  IPC_RETRY_ENABLED = true
else
  IPC_RETRY_ENABLED = match_retry_cfg.enabled
end
local IPC_RETRY_COUNT = match_retry_cfg.count or 5
local IPC_RETRY_SLEEP_MS = match_retry_cfg.sleep_ms or 20
local MAC_ZERO = "00:00:00:00:00:00"
local mac_valid
mac_valid = function(mac)
  return mac ~= "unknown" and mac ~= MAC_ZERO
end
local mac_clients = { }
local ip_to_mac = { }
local pipe_rfd = nil
local sleep_req = ffi.new("timespec_t[1]")
local CLOCK_MONOTONIC = 1
local purge_counter = 0
local _benchmark_ts = ffi.new("timespec_t[1]")
local current_benchmark_ms
current_benchmark_ms = function()
  libc.clock_gettime(CLOCK_MONOTONIC, _benchmark_ts)
  return tonumber(_benchmark_ts[0].tv_sec) * 1000 + math.floor(tonumber(_benchmark_ts[0].tv_nsec) / 1000000)
end
local bench_delta
bench_delta = function(finish, start)
  if not (finish and start) then
    return nil
  end
  local delta = finish - start
  if delta >= 0 then
    return delta
  else
    return nil
  end
end
local build_benchmark_fields
build_benchmark_fields = function(entry, info, deltas)
  local fields = {
    action = "dns_benchmark",
    worker = "dns",
    mac_src = info.client_mac,
    vlan = info.vlan,
    src_ip = info.client_ip,
    dst_ip = info.resolver_ip,
    dst_port = info.client_port,
    txid = string.format("0x%04x", info.txid),
    af = info.af,
    user = info.user,
    qname = info.qname,
    qtype = info.qtype,
    reason = entry.reason,
    rule = entry.rule_id,
    dnsonly = entry.dnsonly,
    q_to_response_ms = deltas.delta_ms,
    question_proc_ms = deltas.question_proc_ms,
    response_entry_ms = deltas.response_entry_ms,
    drain_ms = deltas.drain_ms,
    payload_ms = deltas.payload_ms,
    parse_ms = deltas.parse_ms,
    match_ms = deltas.match_ms,
    log_ms = deltas.log_ms,
    retry_wait_ms = info.retry_wait_ms,
    retry_attempts = info.retry_attempts
  }
  return fields, (entry.refused and "block" or "allow")
end
local update_mac_clients = nil
local drain_ts = 0
local drain_on_msg
drain_on_msg = function(msg)
  return update_mac_clients(msg, drain_ts)
end
local sleep_ms
sleep_ms = function(ms)
  if not (ms and ms > 0) then
    return 
  end
  sleep_req[0].tv_sec = math.floor(ms / 1000)
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  return libc.nanosleep(sleep_req, nil)
end
local retry_pending_match
retry_pending_match = function(txid, client_ip, client_port, resolver_ip)
  if not (IPC_RETRY_ENABLED) then
    return nil, 0, 0
  end
  local tries = IPC_RETRY_COUNT or 0
  local wait_ms = IPC_RETRY_SLEEP_MS or 0
  if tries <= 0 then
    return nil, 0, 0
  end
  local total_wait_ms = 0
  for i = 1, tries do
    sleep_ms(wait_ms)
    total_wait_ms = total_wait_ms + wait_ms
    local ts = now()
    drain_ts = ts
    drain_pipe(pipe_rfd, now, drain_on_msg)
    local entry = get_pending_entry(txid, client_ip, client_port, resolver_ip, now)
    if entry then
      return entry, i, total_wait_ms
    end
  end
  return nil, tries, total_wait_ms
end
update_mac_clients = function(msg, ts)
  local mac = msg.mac_str
  if mac == MAC_ZERO then
    return 
  end
  local entry = mac_clients[mac] or { }
  entry.last_seen = ts
  if msg.ipv4 then
    if not (entry.ipv4 == msg.ip_str) then
      if entry.ipv4 then
        ip_to_mac[entry.ipv4] = nil
      end
      entry.ipv4 = msg.ip_str
      ip_to_mac[msg.ip_str] = mac
    end
  else
    if not (entry.ipv6 == msg.ip_str) then
      if entry.ipv6 then
        ip_to_mac[entry.ipv6] = nil
      end
      entry.ipv6 = msg.ip_str
      ip_to_mac[msg.ip_str] = mac
    end
  end
  mac_clients[mac] = entry
end
local purge_mac_clients
purge_mac_clients = function(ts)
  for mac, entry in pairs(mac_clients) do
    if ts - entry.last_seen > (clients_cfg.expiry or 300) then
      if entry.ipv4 then
        ip_to_mac[entry.ipv4] = nil
      end
      if entry.ipv6 then
        ip_to_mac[entry.ipv6] = nil
      end
      entry.ips = nil
      mac_clients[mac] = nil
      log_info(function()
        return {
          action = "client_expired",
          mac = mac
        }
      end)
    end
  end
end
local resolve_client_family
resolve_client_family = function(ip_str, want)
  local mac = ip_to_mac[ip_str]
  if mac then
    local entry = mac_clients[mac]
    local result = entry and entry[want]
    if result then
      return result
    end
  end
  return nil
end
local finalize_a
finalize_a = function(ctx, override)
  local qh_ptr, pkt_id, raw, ip, l4, ip_ihl, dns_msg, dns_raw, entry
  qh_ptr, pkt_id, raw, ip, l4, ip_ihl, dns_msg, dns_raw, entry = ctx.qh_ptr, ctx.pkt_id, ctx.raw, ctx.ip, ctx.l4, ctx.ip_ihl, ctx.dns_msg, ctx.dns_raw, ctx.entry
  local resolver_ip, dnsonly = ctx.resolver_ip, ctx.dnsonly
  local nft_rule_id, ack_corr = ctx.nft_rule_id, ctx.ack_corr
  local client_ip, client_mac, user = ctx.client_ip, ctx.client_mac, ctx.user
  local txid, vlan = ctx.txid, ctx.vlan
  local src_ip, dst_ip = ctx.src_ip, ctx.dst_ip
  local reason = entry and entry.reason or ""
  local txid_hex = string.format("0x%04x", txid)
  local client_v4, client_v6 = nil, nil
  local client_addr
  client_addr = function(fam)
    if fam == "ipv4" then
      client_v4 = client_v4 or (ip.version == 4 and client_ip or resolve_client_family(client_ip, "ipv4"))
      return client_v4
    else
      client_v6 = client_v6 or (ip.version == 6 and client_ip or resolve_client_family(client_ip, "ipv6"))
      return client_v6
    end
  end
  local inject_opts = {
    client_addr = client_addr,
    client_mac = client_mac,
    user = user,
    rule_id = nft_rule_id,
    wildcard_ids = auth_wildcard_rules,
    ack_corr = ack_corr,
    inject_nft = true,
    mac_valid = mac_valid,
    add_ip = {
      ipv4 = add_ip4,
      ipv6 = add_ip6
    },
    add_mac = {
      ipv4 = add_mac4,
      ipv6 = add_mac6
    }
  }
  local inject_answers
  inject_answers = function(answers)
    drain_ack()
    return inject(answers, inject_opts)
  end
  local patch_and_accept
  patch_and_accept = function(new_dns, action_label)
    if new_dns then
      new_dns = strip_https_rr(new_dns) or new_dns
      local patched = replace_dns_payload(raw, ip, l4, ip_ihl, new_dns)
      if patched then
        log_debug(function()
          return {
            action = action_label,
            src_ip = src_ip,
            dst_ip = dst_ip,
            txid = txid_hex,
            client_mac = client_mac,
            user = user
          }
        end)
        return set_verdict(qh_ptr, pkt_id, NF_ACCEPT, patched)
      end
    end
    return set_verdict(qh_ptr, pkt_id, NF_DROP)
  end
  if override and override.kind == "block" then
    return patch_and_accept(build_nxdomain_response(dns_msg, dns_raw, VALIDATOR_REASON), "response_validator_block")
  end
  if override and override.kind == "sinkhole" then
    local sink = {
      a = override.a or { },
      aaaa = override.aaaa or { },
      ttl = override.ttl
    }
    return patch_and_accept(build_sinkhole_response(dns_msg, dns_raw, VALIDATOR_REASON, sink), "response_validator_sinkhole")
  end
  if override and override.kind == "redirect" and override.cname_target then
    if not (dns_classify.has_cname_target(dns_msg, dns_raw, override.cname_target)) then
      local target_rrs = {
        a = override.a or { },
        aaaa = override.aaaa or { },
        ttl = override.ttl
      }
      local new_dns = build_cname_response(dns_msg, dns_raw, override.cname_target, VALIDATOR_REASON, target_rrs)
      if new_dns then
        new_dns = clear_ad_bit(new_dns)
        local patched = replace_dns_payload(raw, ip, l4, ip_ihl, new_dns)
        if patched then
          local redirect_answers = { }
          local _list_1 = (override.a or { })
          for _index_0 = 1, #_list_1 do
            local r = _list_1[_index_0]
            redirect_answers[#redirect_answers + 1] = {
              family = "ipv4",
              addr = ip2s(r),
              ttl = override.ttl
            }
          end
          local _list_2 = (override.aaaa or { })
          for _index_0 = 1, #_list_2 do
            local r = _list_2[_index_0]
            redirect_answers[#redirect_answers + 1] = {
              family = "ipv6",
              addr = ip2s(r),
              ttl = override.ttl
            }
          end
          if #redirect_answers > 0 then
            inject_answers(redirect_answers)
            local pending_seq = get_last_seq()
            if pending_seq then
              wait_ack(pending_seq, ack_corr, (function()
                return drain_pipe(pipe_rfd, now, drain_on_msg)
              end))
            end
          end
          log_debug(function()
            return {
              action = "response_validator_redirect",
              target = override.cname_target,
              src_ip = src_ip,
              dst_ip = dst_ip,
              txid = txid_hex,
              client_mac = client_mac,
              user = user
            }
          end)
          return set_verdict(qh_ptr, pkt_id, NF_ACCEPT, patched)
        end
      end
      return set_verdict(qh_ptr, pkt_id, NF_DROP)
    end
  end
  local response_hooks = (entry and entry.response_rule_ids and #entry.response_rule_ids > 0) and entry.response_rule_ids or nft_rule_id
  local resp_ctx = run_on_response(response_hooks, dns_raw, reason, {
    resolver_ip = resolver_ip
  })
  dns_raw = resp_ctx.dns_raw
  local payload_modified = resp_ctx.modified
  local inject_nft = resp_ctx.inject_nft
  local answers_dns = dns_msg
  local parsed_modified, _ = parse_dns(dns_raw, 1, false)
  if parsed_modified then
    answers_dns = parsed_modified
  end
  local answers = { }
  local _list_1 = parse_answers(answers_dns)
  for _index_0 = 1, #_list_1 do
    local a = _list_1[_index_0]
    if a.rtype == QTYPE.A or a.rtype == QTYPE.AAAA then
      local fam = a.rtype == QTYPE.AAAA and "ipv6" or "ipv4"
      answers[#answers + 1] = {
        family = fam,
        addr = a.rdata_str,
        ttl = a.ttl
      }
    end
  end
  if inject_nft and not dnsonly then
    drain_ack()
  end
  inject_opts.inject_nft = inject_nft
  local inj = inject(answers, inject_opts)
  local ip_count = inj.ip_count
  local records_to_add = inj.records_to_add
  local success_any = inj.success_any
  for fam, recs in pairs({
    ipv4 = inj.no_v4,
    ipv6 = inj.no_v6
  }) do
    if #recs > 0 then
      local log_fn
      if mac_valid(client_mac) then
        log_fn = log_info
      else
        log_fn = log_warn
      end
      log_fn(function()
        return {
          action = "no_" .. tostring(fam) .. "_for_client",
          client = client_ip,
          count = #recs,
          records = table.concat(recs, " "),
          reason = "client_" .. tostring(fam) .. "_unknown",
          mac_fallback = mac_valid(client_mac),
          user = user
        }
      end)
    end
  end
  local new_dns, dns_modified = patch_modified_dns(dns_raw, reason)
  payload_modified = payload_modified or dns_modified
  local patched = nil
  if payload_modified then
    patched = replace_dns_payload(raw, ip, l4, ip_ihl, new_dns)
    if not (patched) then
      return set_verdict(qh_ptr, pkt_id, NF_DROP)
    end
  end
  local qnames = table.concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    local _list_2 = dns_msg.questions
    for _index_0 = 1, #_list_2 do
      local q = _list_2[_index_0]
      _accum_0[_len_0] = q.name
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)(), ",")
  log_debug(function()
    return {
      action = resp_ctx.action_label or (payload_modified and "response_patched" or "response_allow"),
      src_ip = src_ip,
      dst_ip = dst_ip,
      vlan = vlan,
      txid = txid_hex,
      qnames = qnames,
      answers = ip_count,
      nft_rule_id = nft_rule_id,
      payload_modified = payload_modified,
      rcode = dns_msg.header.rcode,
      client_mac = client_mac,
      user = user
    }
  end)
  if records_to_add > 0 and not success_any then
    if ((config.nft or { }).add_failure_policy or "fail-closed") == "fail-closed" then
      log_debug(function()
        return {
          action = "nft_add_failed_policy_fail_closed",
          txid = txid_hex,
          client_ip = client_ip,
          qnames = qnames,
          user = user
        }
      end)
      return set_verdict(qh_ptr, pkt_id, NF_DROP)
    else
      log_warn(function()
        return {
          action = "nft_add_failed_fail_open",
          txid = txid_hex,
          client_ip = client_ip,
          qnames = qnames,
          user = user
        }
      end)
    end
  end
  if not dnsonly and records_to_add > 0 then
    local pending_seq = get_last_seq()
    if pending_seq then
      wait_ack(pending_seq, ack_corr, (function()
        return drain_pipe(pipe_rfd, now, drain_on_msg)
      end))
    end
  end
  if payload_modified then
    return set_verdict(qh_ptr, pkt_id, NF_ACCEPT, patched)
  else
    return set_verdict(qh_ptr, pkt_id, NF_ACCEPT)
  end
end
local sweep_parked
sweep_parked = function()
  if not (so_state and so_state.has_parked()) then
    return 
  end
  local _list_1 = so_state.expired(current_benchmark_ms())
  for _index_0 = 1, #_list_1 do
    local ctx = _list_1[_index_0]
    finalize_a(ctx, nil)
  end
end
local try_upstream_retry
try_upstream_retry = function(entry, dns_msg, dns_raw, ip, l4, resolver_ip)
  if not (retry_enabled) then
    return false
  end
  if entry.refused then
    return false
  end
  if not (l4.proto == "udp") then
    return false
  end
  local rc = bit.band(dns_msg.header.ra_z_rcode, 0x0f)
  local q1 = dns_msg.questions and dns_msg.questions[1]
  local qname = q1 and q1.name and q1.name:lower()
  if rc == 0 then
    nxdomain_bad.remove(qname)
    return false
  end
  if not (retry_rcodes[rc]) then
    return false
  end
  if rc == RCODE_NXDOMAIN and nxdomain_bad.has(qname) then
    return false
  end
  if not ((entry.upstream_retries or 0) < retry_max) then
    if rc == RCODE_NXDOMAIN then
      nxdomain_bad.add(qname)
    end
    return false
  end
  local fd = retry_fds[ip.version == 6 and "ipv6" or "ipv4"]
  if not (fd) then
    return false
  end
  local qdcount = dns_msg.header.qdcount or (dns_msg.questions and #dns_msg.questions) or 1
  local query_raw = build_query_from_response(dns_raw, qdcount)
  if not (query_raw) then
    return false
  end
  local pkt = dup_query.build_query(ip, l4, query_raw)
  if not (pkt) then
    return false
  end
  entry.upstream_retries = (entry.upstream_retries or 0) + 1
  entry.expire = now() + pending_ttl
  raw_send.send(fd, ip.version, pkt, resolver_ip)
  return true
end
local arm_retry_fds
arm_retry_fds = function()
  if not (retry_enabled) then
    return 
  end
  for fam, ver in pairs({
    ipv4 = 4,
    ipv6 = 6
  }) do
    local _continue_0 = false
    repeat
      if retry_fds[fam] then
        _continue_0 = true
        break
      end
      local fd = raw_send.open(ver)
      if fd then
        retry_fds[fam] = fd
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
end
local make_override
make_override = function(vi)
  local _exp_0 = vi.verdict
  if "block" == _exp_0 then
    return {
      kind = "block"
    }
  elseif "sinkhole" == _exp_0 then
    return {
      kind = "sinkhole",
      a = vi.a,
      aaaa = vi.aaaa,
      ttl = vi.ttl
    }
  elseif "redirect" == _exp_0 then
    return {
      kind = "redirect",
      cname_target = vi.cname_target,
      a = vi.a,
      aaaa = vi.aaaa,
      ttl = vi.ttl
    }
  else
    return {
      kind = "pass"
    }
  end
end
local handle_response
handle_response = function(qh_ptr, nfad, pkt_id)
  local bench_start_ms
  if runtime_cfg.benchmark then
    bench_start_ms = current_benchmark_ms()
  else
    bench_start_ms = nil
  end
  local bench_after_drain_ms = nil
  local bench_after_payload_ms = nil
  local bench_after_parse_ms = nil
  local bench_after_match_ms = nil
  local ts = now()
  drain_ts = ts
  drain_pipe(pipe_rfd, now, drain_on_msg)
  if runtime_cfg.benchmark then
    bench_after_drain_ms = current_benchmark_ms()
  end
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  if runtime_cfg.benchmark then
    bench_after_payload_ms = current_benchmark_ms()
  end
  local l2 = get_l2(nfad)
  local ip, l4, dns_msg, dns_raw, ip_ihl = parse_packet(raw)
  if runtime_cfg.benchmark then
    bench_after_parse_ms = current_benchmark_ms()
  end
  if not (ip) then
    if l4 == "buffering" then
      return NF_DROP
    end
    return NF_ACCEPT
  end
  purge_counter = (purge_counter + 1) % 1000
  if purge_counter == 0 then
    tcp_state.purge()
    purge_mac_clients(ts)
  end
  if not (dns_msg.header.qr) then
    return NF_ACCEPT
  end
  local src_ip = ip2s(ip.src)
  local dst_ip = ip2s(ip.dst)
  local client_port = l4.dpt
  local txid = dns_msg.header.id
  local txid_hex = string.format("0x%04x", txid)
  local client_ip = dst_ip
  local resolver_ip = src_ip
  local client_mac = ip_to_mac[client_ip] or "unknown"
  local user = user_for_mac(client_mac, client_ip, auth_cfg.sessions_file or "/tmp/sessions.lua")
  local direct_validator = false
  if so_state and so_state.is_validator(resolver_ip) then
    if get_pending_entry(txid, dst_ip, client_port, resolver_ip, now) then
      direct_validator = true
    else
      local q1 = dns_msg.questions and dns_msg.questions[1]
      if q1 then
        local key = so_state.corr_key(client_ip, txid, q1.name)
        local override = make_override(dns_classify.classify(dns_msg, dns_raw))
        local parked_ctx = so_state.take_parked(key)
        if parked_ctx then
          finalize_a(parked_ctx, override)
        else
          so_state.store_verdict(key, override, ts)
        end
      end
      return NF_DROP
    end
  end
  local entry = get_pending_entry(txid, dst_ip, client_port, resolver_ip, now)
  local retry_attempts = 0
  local retry_wait_ms = 0
  if not (entry) then
    entry, retry_attempts, retry_wait_ms = retry_pending_match(txid, dst_ip, client_port, resolver_ip)
    if entry then
      log_info(function()
        return {
          action = "response_matched_after_retry",
          src_ip = src_ip,
          dst_ip = dst_ip,
          txid = txid_hex,
          retry_attempts = retry_attempts,
          retry_wait_ms = retry_wait_ms,
          user = user
        }
      end)
    else
      log_debug(function()
        return {
          action = (function()
            if retry_attempts > 0 then
              return "response_no_matching_question_after_retry"
            else
              return "response_no_matching_question"
            end
          end)(),
          src_ip = src_ip,
          dst_ip = dst_ip,
          vlan = l2.vlan,
          txid = txid_hex,
          rcode = dns_msg.header.rcode,
          client_mac = client_mac,
          retry_attempts = retry_attempts,
          retry_wait_ms = retry_wait_ms,
          user = user
        }
      end)
      return NF_DROP
    end
  end
  if runtime_cfg.benchmark then
    bench_after_match_ms = current_benchmark_ms()
  end
  if try_upstream_retry(entry, dns_msg, dns_raw, ip, l4, resolver_ip) then
    local q1 = dns_msg.questions and dns_msg.questions[1]
    log_debug(function()
      return {
        action = "response_upstream_retry",
        src_ip = src_ip,
        dst_ip = dst_ip,
        vlan = l2.vlan,
        txid = txid_hex,
        qname = q1 and q1.name or "-",
        rcode = bit.band(dns_msg.header.ra_z_rcode, 0x0f),
        attempt = entry.upstream_retries,
        resolver = resolver_ip,
        client_mac = client_mac,
        user = user
      }
    end)
    return NF_DROP
  end
  consume(txid, dst_ip, client_port, resolver_ip)
  if runtime_cfg.benchmark and entry and entry.benchmark_ms then
    local bench_log_ms = current_benchmark_ms()
    local delta_ms = bench_log_ms - entry.benchmark_ms
    if delta_ms >= 0 then
      local q1 = dns_msg.questions and dns_msg.questions[1]
      local info = {
        client_mac = client_mac,
        vlan = l2.vlan,
        client_ip = client_ip,
        resolver_ip = resolver_ip,
        client_port = client_port,
        txid = txid,
        af = ip.version == 6 and "ipv6" or "ipv4",
        user = user,
        qname = q1 and q1.name or "-",
        qtype = q1 and (QTYPE[q1.qtype] or "TYPE" .. tostring(q1.qtype)) or "-",
        retry_wait_ms = retry_wait_ms,
        retry_attempts = retry_attempts
      }
      local question_proc_ms = entry.question_proc_ms or 0
      local q_exit_ms = entry.benchmark_ms + question_proc_ms
      local deltas = {
        delta_ms = delta_ms,
        question_proc_ms = question_proc_ms,
        response_entry_ms = bench_delta(bench_start_ms, q_exit_ms),
        drain_ms = bench_delta(bench_after_drain_ms, bench_start_ms),
        payload_ms = bench_delta(bench_after_payload_ms, bench_after_drain_ms),
        parse_ms = bench_delta(bench_after_parse_ms, bench_after_payload_ms),
        match_ms = bench_delta(bench_after_match_ms, bench_after_parse_ms),
        log_ms = bench_delta(bench_log_ms, bench_after_match_ms)
      }
      local bench_fields, verdict = build_benchmark_fields(entry, info, deltas)
      if verdict == "block" then
        log_block(function()
          return bench_fields
        end)
      else
        log_allow(function()
          return bench_fields
        end)
      end
    end
  end
  local refused = entry and entry.refused or false
  local dnsonly = entry and entry.dnsonly or false
  local nft_rule_id = (entry and entry.rule_id and #entry.rule_id > 0) and entry.rule_id or "unknown_rule"
  local ack_corr = string.format("%04x:%s:%d:%s", txid, dst_ip, client_port, resolver_ip)
  if refused then
    local nxdomain_mod = entry.modifiers and entry.modifiers.nxdomain
    local refused_dns
    if nxdomain_mod then
      refused_dns = build_nxdomain_response(dns_msg, dns_raw, entry.reason)
    else
      refused_dns = build_blocked_response(dns_msg, dns_raw, entry.reason)
    end
    if not (refused_dns) then
      return NF_DROP
    end
    refused_dns = strip_https_rr(refused_dns) or refused_dns
    local patched = replace_dns_payload(raw, ip, l4, ip_ihl, refused_dns)
    if not (patched) then
      return NF_DROP
    end
    local qnames = table.concat((function()
      local _accum_0 = { }
      local _len_0 = 1
      local _list_1 = dns_msg.questions
      for _index_0 = 1, #_list_1 do
        local q = _list_1[_index_0]
        _accum_0[_len_0] = q.name
        _len_0 = _len_0 + 1
      end
      return _accum_0
    end)(), ",")
    log_debug(function()
      return {
        action = nxdomain_mod and "response_nxdomain" or "response_refused",
        src_ip = src_ip,
        dst_ip = dst_ip,
        vlan = l2.vlan,
        txid = txid_hex,
        qnames = qnames,
        client_mac = client_mac,
        user = user
      }
    end)
    local patched_ptr = ffi.cast("const unsigned char*", patched)
    libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr)
    return -1
  end
  local ctx = {
    qh_ptr = qh_ptr,
    pkt_id = pkt_id,
    raw = raw,
    ip = ip,
    l4 = l4,
    ip_ihl = ip_ihl,
    dns_msg = dns_msg,
    dns_raw = dns_raw,
    entry = entry,
    resolver_ip = resolver_ip,
    dnsonly = dnsonly,
    nft_rule_id = nft_rule_id,
    ack_corr = ack_corr,
    client_ip = client_ip,
    client_mac = client_mac,
    user = user,
    txid = txid,
    vlan = l2.vlan,
    src_ip = src_ip,
    dst_ip = dst_ip
  }
  local do_so = entry and entry.modifiers and entry.modifiers.validate
  local q1 = dns_msg.questions and dns_msg.questions[1]
  if so_state and q1 and do_so and so_state.active_for(ip.version) and not direct_validator then
    local key = so_state.corr_key(client_ip, txid, q1.name)
    local override = so_state.take_verdict(key, ts)
    if override then
      finalize_a(ctx, override)
    else
      so_state.park(key, ctx, current_benchmark_ms())
    end
    return -1
  end
  finalize_a(ctx, nil)
  return -1
end
local run
run = function(queue_num, rfd, rules_metadata)
  set_action_prefix("response_")
  if rules_metadata then
    load_auth_wildcard_rules(rules_metadata)
  end
  if type(rfd) == "table" then
    local nft_q = require("nft_queue")
    if rfd.nft_wfd then
      nft_q.set_wfd(rfd.nft_wfd)
    end
    if rfd.ack_rfd and rfd.worker_idx ~= nil then
      nft_q.set_ack_rfd(rfd.ack_rfd, rfd.worker_idx)
    end
    rfd = rfd.question_response_rfd
  end
  pipe_rfd = rfd
  local collect_all_resolvers
  collect_all_resolvers = function()
    local seen = { }
    local all = { }
    local add
    add = function(r)
      if not (seen[r]) then
        seen[r] = true
        all[#all + 1] = r
      end
    end
    local _list_1 = (so_cfg.resolvers or { })
    for _index_0 = 1, #_list_1 do
      local r = _list_1[_index_0]
      add(r)
    end
    local _list_2 = (rules_metadata or { })
    for _index_0 = 1, #_list_2 do
      local meta = _list_2[_index_0]
      local _list_3 = (meta.validate_resolvers or { })
      for _index_1 = 1, #_list_3 do
        local r = _list_3[_index_1]
        add(r)
      end
    end
    return all
  end
  if retry_enabled then
    arm_retry_fds()
    log_info(function()
      return {
        action = "dns_upstream_retry_armed",
        max_attempts = retry_max,
        ipv4 = retry_fds.ipv4 ~= nil,
        ipv6 = retry_fds.ipv6 ~= nil
      }
    end)
  end
  local run_opts
  local all_resolvers = collect_all_resolvers()
  if #all_resolvers > 0 then
    local families = { }
    for fam, ver in pairs({
      ipv4 = 4,
      ipv6 = 6
    }) do
      local v_ip = dup_query.pick_resolver(all_resolvers, ver)
      families[fam] = (v_ip and raw_send.routable(ver, v_ip)) and true or false
    end
    if families.ipv4 or families.ipv6 then
      so_state = second_opinion.new({
        resolvers = all_resolvers,
        budget_ms = so_cfg.budget_ms or 80,
        verdict_ttl_s = 5,
        families = families
      })
      run_opts = {
        idle_ms = so_cfg.budget_ms or 80,
        on_idle = sweep_parked
      }
      log_info(function()
        return {
          action = "dns_validator_responses_armed",
          resolvers = table.concat(all_resolvers, ","),
          ipv4 = families.ipv4,
          ipv6 = families.ipv6
        }
      end)
    end
  end
  return run_queue(tonumber(queue_num), handle_response, run_opts)
end
return {
  run = run,
  rr_timeout = rr_timeout,
  patch_modified_dns = patch_modified_dns,
  bench_delta = bench_delta,
  build_benchmark_fields = build_benchmark_fields,
  skip_ipv6_ext_hdrs = skip_ipv6_ext_hdrs,
  dns_tcp_complete = dns_tcp_complete,
  new_dns_tcp_stream = new_dns_tcp_stream,
  try_upstream_retry = try_upstream_retry,
  arm_retry_fds = arm_retry_fds
}
