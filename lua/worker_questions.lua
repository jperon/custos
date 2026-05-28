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
local get_l2
get_l2 = require("nfq/ethernet").get_l2
local parse_ip4
parse_ip4 = require("ipparse.l3.ip4").parse
local parse_ip6
parse_ip6 = require("ipparse.l3.ip6").parse
local parse_udp
parse_udp = require("ipparse.l4.udp").parse
local parse_tcp
parse_tcp = require("ipparse.l4.tcp").parse
local parse_dns, dns_types
do
  local _obj_0 = require("ipparse.l7.dns")
  parse_dns, dns_types = _obj_0.parse, _obj_0.types
end
local ip2s
ip2s = require("ipparse.l3.ip").ip2s
local new_stream
new_stream = require("ipparse.l4.tcp_stream").new
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
local log_allow, log_block, log_warn, log_debug, log_info, set_action_prefix
do
  local _obj_0 = require("log")
  log_allow, log_block, log_warn, log_debug, log_info, set_action_prefix = _obj_0.log_allow, _obj_0.log_block, _obj_0.log_warn, _obj_0.log_debug, _obj_0.log_info, _obj_0.set_action_prefix
end
local user_for_mac
user_for_mac = require("auth.sessions").user_for_mac
local forge_dns = require("forge_dns")
local detect_captive_ips
detect_captive_ips = require("captive_ips").detect
local bridge_raw = require("bridge_raw")
local new_eth, IP4, IP6
do
  local _obj_0 = require("ipparse.l2.ethernet")
  new_eth, IP4, IP6 = _obj_0.new, _obj_0.proto.IP4, _obj_0.proto.IP6
end
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
local domain_from_url
domain_from_url = function(url)
  if not (url) then
    return nil
  end
  local host = url:match("^https?://([^/:]+)")
  if not (host) then
    return nil
  end
  if host:match("^%d+%.%d+%.%d+%.%d+$") then
    return nil
  end
  if host:match("^%[") then
    return nil
  end
  return host:lower()
end
local write_learn_msg
write_learn_msg = function(ip_raw, mac_raw)
  if not (mac_learn_wfd and mac_learn_wfd >= 0) then
    return false
  end
  if not (ip_raw and (#ip_raw == 4 or #ip_raw == 16)) then
    return false
  end
  if not (mac_raw and #mac_raw == 6) then
    return false
  end
  local msg = ffi.new("uint8_t[22]")
  if #ip_raw == 4 then
    for i = 1, 4 do
      msg[i - 1] = ip_raw:byte(i)
    end
  else
    for i = 1, 16 do
      msg[i - 1] = ip_raw:byte(i)
    end
  end
  for i = 1, 6 do
    msg[15 + i] = mac_raw:byte(i)
  end
  local n = libc.write(mac_learn_wfd, msg, 22)
  return n == 22
end
local tsv_field
tsv_field = function(v)
  local s
  if v ~= nil then
    s = tostring(v)
  else
    s = ""
  end
  if #s == 0 then
    return "-"
  else
    return s
  end
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
local PROTO_UDP = 17
local PROTO_TCP = 6
local IPV6_EXT_HDRS = {
  [0] = true,
  [43] = true,
  [44] = true,
  [51] = false,
  [60] = true,
  [135] = true,
  [139] = true,
  [140] = true
}
local skip_ipv6_ext_hdrs
skip_ipv6_ext_hdrs = function(p, len, first_nh)
  local nh = first_nh
  local off = 40
  while IPV6_EXT_HDRS[nh] ~= nil do
    if off + 2 > len then
      return nil, nil
    end
    local next_nh = p[off]
    local ext_size
    if nh == 51 then
      ext_size = (p[off + 1] + 2) * 4
    else
      ext_size = (p[off + 1] + 1) * 8
    end
    if ext_size < 8 or off + ext_size > len then
      return nil, nil
    end
    off = off + ext_size
    nh = next_nh
  end
  return nh, off
end
local dns_tcp_complete
dns_tcp_complete = function(buf)
  if #buf < 2 then
    return false
  end
  return #buf >= 2 + buf:byte(1) * 256 + buf:byte(2)
end
local tcp_state = new_stream(dns_tcp_complete)
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
  if ip.version == 6 then
    local p = ffi.cast("const uint8_t*", raw)
    local l4_off_0based
    proto, l4_off_0based = skip_ipv6_ext_hdrs(p, #raw, ip.next_header)
    if not (proto) then
      return nil, "parse_failed"
    end
    l4_off = l4_off_0based + 1
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
    return ip, udp, dns_msg
  elseif proto == PROTO_TCP then
    local tcp, _ = parse_tcp(raw, l4_off)
    if not (tcp) then
      return nil, "parse_failed"
    end
    local payload = raw:sub(tcp.data_off)
    local is_fin_rst = bit.band(tcp.flags, 0x05) ~= 0
    local has_payload = payload ~= ""
    local key = tostring(ip2s(ip.src)) .. "|" .. tostring(tcp.spt) .. "|" .. tostring(ip2s(ip.dst)) .. "|" .. tostring(tcp.dpt)
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
    return ip, tcp, dns_msg
  end
  return nil, "parse_failed"
end
local handle_question
handle_question = function(qh_ptr, nfad, pkt_id)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local l2 = get_l2(nfad)
  local ip, l4, dns_msg = parse_packet(raw)
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
  else
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
  if captive_domain and raw_fd and _bridge_mac and l4.proto == "udp" then
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
        local forged_ip = forge_dns.forge_dns_response(ip, l4, dns_msg.header.id, q, captive_ip4, captive_ip6)
        if forged_ip then
          local ethertype = ip.version == 6 and IP6 or IP4
          local eth_bytes = tostring(new_eth({
            src = _bridge_mac,
            dst = mac_raw,
            protocol = ethertype,
            vlan = l2.vlan,
            data = forged_ip
          }))
          local ok = bridge_raw.send(raw_fd, eth_bytes, _ifindex)
          log_info(function()
            return {
              action = "dns_stolen",
              domain = q.name,
              qtype = dns_types[q.qtype] or "TYPE" .. tostring(q.qtype),
              src_ip = src_ip,
              resolver = dst_ip,
              mac = l2.mac_src,
              ancount = (captive_ip4 and q.qtype == 1 or captive_ip6 and q.qtype == 28) and 1 or 0,
              sent = ok
            }
          end)
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
  local q_fields = {
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
    local allowed, reason, rule_id, nft_timeout = nil, nil, nil, nil
    local decision
    if filter.decide_meta then
      decision = filter.decide_meta(req)
    else
      decision = nil
    end
    if decision then
      allowed = decision.verdict
      reason = decision.reason
      rule_id = decision.rule_id
      nft_timeout = decision.timeout
    else
      allowed, reason, rule_id = filter.decide(req)
      nft_timeout = nil
    end
    q_fields.reason = reason or (allowed and "allowed") or "denied"
    q_fields.rule = rule_id or ""
    if allowed then
      log_allow(function()
        return q_fields
      end)
      if rule_id then
        metrics.record_verdict(rule_id, "allow")
      end
      allow_reason = reason
      allow_rule_id = rule_id
      allow_timeout = nft_timeout
    else
      log_block(function()
        return q_fields
      end)
      if rule_id then
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
  local benchmark_ms = get_benchmark_ms()
  allow_timeout = allow_timeout or nft_cfg.ip_timeout
  block_timeout = block_timeout or nft_cfg.ip_timeout
  if verdict == NF_ACCEPT then
    q_fields.timeout = allow_timeout
  else
    q_fields.timeout = block_timeout
  end
  local ipc_ok = false
  if verdict == NF_ACCEPT then
    ipc_ok = write_msg(pipe_wfd, dns_msg.header.id, ip.src, l4.spt, l2.mac_raw, ip.dst, allow_reason, benchmark_ms, allow_rule_id, allow_timeout)
  else
    ipc_ok = write_refused_msg(pipe_wfd, dns_msg.header.id, ip.src, l4.spt, l2.mac_raw, ip.dst, block_reason, benchmark_ms, block_rule_id, block_timeout, block_modifiers)
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
  return NF_ACCEPT
end
local run
run = function(queue_num, wfd, learn_wfd, ev_wfd, filter_data)
  set_action_prefix("questions_")
  metrics.init(config.metrics)
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
      local ifname = auth.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"
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
  end
  return run_queue(tonumber(queue_num), handle_question)
end
return {
  run = run
}
