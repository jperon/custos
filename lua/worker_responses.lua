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
local parse_ip4
parse_ip4 = require("ipparse.l3.ip4").parse
local parse_ip6
parse_ip6 = require("ipparse.l3.ip6").parse
local parse_udp
parse_udp = require("ipparse.l4.udp").parse
local parse_tcp
parse_tcp = require("ipparse.l4.tcp").parse
local parse_dns, QTYPE
do
  local _obj_0 = require("ipparse.l7.dns")
  parse_dns, QTYPE = _obj_0.parse, _obj_0.types
end
local ip2s
ip2s = require("ipparse.l3.ip").ip2s
local new_stream
new_stream = require("ipparse.l4.tcp_stream").new
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
local log_info, log_warn, log_debug, now, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug, now, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug, _obj_0.now, _obj_0.set_action_prefix
end
local build_blocked_response, strip_https_rr, add_ede_modified, clear_ad_bit
do
  local _obj_0 = require("dns_ede")
  build_blocked_response, strip_https_rr, add_ede_modified, clear_ad_bit = _obj_0.build_blocked_response, _obj_0.strip_https_rr, _obj_0.add_ede_modified, _obj_0.clear_ad_bit
end
local bit = require("bit")
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
local r16
r16 = function(p, o)
  return bit.bor(bit.lshift(p[o], 8), p[o + 1])
end
local w32
w32 = function(p, o, v)
  p[o] = bit.band(bit.rshift(v, 24), 0xFF)
  p[o + 1] = bit.band(bit.rshift(v, 16), 0xFF)
  p[o + 2] = bit.band(bit.rshift(v, 8), 0xFF)
  p[o + 3] = bit.band(v, 0xFF)
end
local w16
w16 = function(p, o, v)
  p[o] = bit.band(bit.rshift(v, 8), 0xFF)
  p[o + 1] = bit.band(v, 0xFF)
end
local fix_ip4_cksum
fix_ip4_cksum = function(buf, ihl)
  buf[10] = 0
  buf[11] = 0
  local sum = 0
  for i = 0, ihl - 1, 2 do
    sum = sum + bit.bor(bit.lshift(buf[i], 8), buf[i + 1])
  end
  while bit.rshift(sum, 16) ~= 0 do
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  end
  return w16(buf, 10, bit.band(bit.bnot(sum), 0xFFFF))
end
local fix_udp4_cksum
fix_udp4_cksum = function(buf, pkt_len, ihl)
  local udp_off = ihl
  if pkt_len < udp_off + 8 then
    return 
  end
  local udp_len = r16(buf, udp_off + 4)
  buf[udp_off + 6] = 0
  buf[udp_off + 7] = 0
  local sum = 0
  for i = 12, 18, 2 do
    sum = sum + r16(buf, i)
  end
  sum = sum + PROTO_UDP
  sum = sum + udp_len
  local udp_end = udp_off + udp_len
  if udp_end > pkt_len then
    udp_end = pkt_len
  end
  local cksum_off = udp_off + 6
  local i = udp_off
  while i < udp_end do
    local word
    if i == cksum_off then
      word = 0
    elseif i + 1 < udp_end then
      word = r16(buf, i)
    else
      word = bit.lshift(buf[i], 8)
    end
    sum = sum + word
    i = i + 2
  end
  while bit.rshift(sum, 16) ~= 0 do
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  end
  local cksum = bit.band(bit.bnot(sum), 0xFFFF)
  if cksum == 0 then
    cksum = 0xFFFF
  end
  return w16(buf, udp_off + 6, cksum)
end
local fix_udp6_cksum
fix_udp6_cksum = function(buf, pkt_len, l4_off)
  local udp_off = l4_off
  if pkt_len < udp_off + 8 then
    return 
  end
  local udp_len = r16(buf, udp_off + 4)
  buf[udp_off + 6] = 0
  buf[udp_off + 7] = 0
  local sum = 0
  for i = 8, 38, 2 do
    sum = sum + r16(buf, i)
  end
  sum = sum + udp_len
  sum = sum + PROTO_UDP
  local udp_end = udp_off + udp_len
  if udp_end > pkt_len then
    udp_end = pkt_len
  end
  local cksum_off = udp_off + 6
  local i = udp_off
  while i < udp_end do
    local word
    if i == cksum_off then
      word = 0
    elseif i + 1 < udp_end then
      word = r16(buf, i)
    else
      word = bit.lshift(buf[i], 8)
    end
    sum = sum + word
    i = i + 2
  end
  while bit.rshift(sum, 16) ~= 0 do
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  end
  local cksum = bit.band(bit.bnot(sum), 0xFFFF)
  if cksum == 0 then
    cksum = 0xFFFF
  end
  return w16(buf, udp_off + 6, cksum)
end
local fix_tcp4_cksum
fix_tcp4_cksum = function(buf, pkt_len, ihl)
  local tcp_off = ihl
  if pkt_len < tcp_off + 20 then
    return 
  end
  local tcp_len = pkt_len - tcp_off
  buf[tcp_off + 16] = 0
  buf[tcp_off + 17] = 0
  local sum = 0
  for i = 12, 18, 2 do
    sum = sum + r16(buf, i)
  end
  sum = sum + PROTO_TCP
  sum = sum + tcp_len
  local tcp_end = tcp_off + tcp_len
  if tcp_end > pkt_len then
    tcp_end = pkt_len
  end
  local cksum_off = tcp_off + 16
  local i = tcp_off
  while i < tcp_end do
    local word
    if i == cksum_off then
      word = 0
    elseif i + 1 < tcp_end then
      word = r16(buf, i)
    else
      word = bit.lshift(buf[i], 8)
    end
    sum = sum + word
    i = i + 2
  end
  while bit.rshift(sum, 16) ~= 0 do
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  end
  local cksum = bit.band(bit.bnot(sum), 0xFFFF)
  if cksum == 0 then
    cksum = 0xFFFF
  end
  return w16(buf, tcp_off + 16, cksum)
end
local fix_tcp6_cksum
fix_tcp6_cksum = function(buf, pkt_len, l4_off)
  local tcp_off = l4_off
  if pkt_len < tcp_off + 20 then
    return 
  end
  local tcp_len = pkt_len - tcp_off
  buf[tcp_off + 16] = 0
  buf[tcp_off + 17] = 0
  local sum = 0
  for i = 8, 38, 2 do
    sum = sum + r16(buf, i)
  end
  sum = sum + tcp_len
  sum = sum + PROTO_TCP
  local tcp_end = tcp_off + tcp_len
  if tcp_end > pkt_len then
    tcp_end = pkt_len
  end
  local cksum_off = tcp_off + 16
  local i = tcp_off
  while i < tcp_end do
    local word
    if i == cksum_off then
      word = 0
    elseif i + 1 < tcp_end then
      word = r16(buf, i)
    else
      word = bit.lshift(buf[i], 8)
    end
    sum = sum + word
    i = i + 2
  end
  while bit.rshift(sum, 16) ~= 0 do
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  end
  local cksum = bit.band(bit.bnot(sum), 0xFFFF)
  if cksum == 0 then
    cksum = 0xFFFF
  end
  return w16(buf, tcp_off + 16, cksum)
end
local replace_dns_payload
replace_dns_payload = function(raw, ip, l4, ip_ihl, new_dns)
  local p = ffi.cast("const uint8_t*", raw)
  local dns_len = #new_dns
  if l4.proto == "udp" then
    local udp_len = 8 + dns_len
    local new_pkt_len = ip_ihl + udp_len
    local new_buf = ffi.new("uint8_t[?]", new_pkt_len)
    ffi.copy(new_buf, p, ip_ihl + 8)
    w16(new_buf, ip_ihl + 4, udp_len)
    ffi.copy(new_buf + ip_ihl + 8, new_dns, dns_len)
    if ip.version == 4 then
      w16(new_buf, 2, new_pkt_len)
      fix_udp4_cksum(new_buf, new_pkt_len, ip_ihl)
      fix_ip4_cksum(new_buf, ip_ihl)
    elseif ip.version == 6 then
      w16(new_buf, 4, (ip_ihl - 40) + udp_len)
      fix_udp6_cksum(new_buf, new_pkt_len, ip_ihl)
    end
    return ffi.string(new_buf, new_pkt_len)
  elseif l4.proto == "tcp" then
    local tcp_hdr_len = bit.rshift(p[ip_ihl + 12], 4) * 4
    local hdr_len = ip_ihl + tcp_hdr_len
    local new_pkt_len = hdr_len + 2 + dns_len
    local new_buf = ffi.new("uint8_t[?]", new_pkt_len)
    ffi.copy(new_buf, p, hdr_len)
    w16(new_buf, hdr_len, dns_len)
    ffi.copy(new_buf + hdr_len + 2, new_dns, dns_len)
    w32(new_buf, ip_ihl + 4, l4.tcp_init_seq)
    new_buf[ip_ihl + 13] = 0x18
    if ip.version == 4 then
      w16(new_buf, 2, new_pkt_len)
      fix_tcp4_cksum(new_buf, new_pkt_len, ip_ihl)
      fix_ip4_cksum(new_buf, ip_ihl)
    elseif ip.version == 6 then
      w16(new_buf, 4, (ip_ihl - 40) + tcp_hdr_len + 2 + dns_len)
      fix_tcp6_cksum(new_buf, new_pkt_len, ip_ihl)
    end
    return ffi.string(new_buf, new_pkt_len)
  end
  return nil
end
local decode_simple_cname
decode_simple_cname = function(rdata)
  local parts = { }
  local pos = 1
  while pos <= #rdata do
    local len = rdata:byte(pos)
    if len == 0 then
      break
    end
    if bit.band(len, 0xC0) == 0xC0 then
      return "(cname)"
    end
    parts[#parts + 1] = rdata:sub(pos + 1, pos + len)
    pos = pos + (1 + len)
  end
  return table.concat(parts, ".")
end
local fmt_rdata
fmt_rdata = function(rr)
  if (rr.rtype == 1 or rr.rtype == 28) and (#rr.rdata == 4 or #rr.rdata == 16) then
    return ip2s(rr.rdata)
  elseif rr.rtype == 5 then
    return decode_simple_cname(rr.rdata)
  else
    return "(rdata " .. tostring(#rr.rdata) .. "B)"
  end
end
local parse_answers
parse_answers = function(dns_msg)
  local _accum_0 = { }
  local _len_0 = 1
  local _list_0 = dns_msg.answers
  for _index_0 = 1, #_list_0 do
    local rr = _list_0[_index_0]
    _accum_0[_len_0] = {
      name = rr.name,
      rtype = rr.rtype,
      rclass = rr.rclass,
      ttl = rr.ttl,
      rdlength = #rr.rdata,
      rdata_raw = (rr.rtype == 1 or rr.rtype == 28) and rr.rdata or "",
      rdata_str = fmt_rdata(rr),
      rtype_name = QTYPE[rr.rtype] or "TYPE" .. tostring(rr.rtype),
      ttl_offset = rr.off + #rr.rname + 3
    }
    _len_0 = _len_0 + 1
  end
  return _accum_0
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
    return ip, tcp, dns_msg, dns_raw, ip_ihl
  end
  return nil, "parse_failed"
end
local _filter = nil
local get_rule_on_response
get_rule_on_response = function(rule_id)
  _filter = _filter or require("filter")
  return _filter.get_rule_on_response(rule_id)
end
local rules_metadata = nil
local auth_wildcard_rules = { }
local load_auth_wildcard_rules
load_auth_wildcard_rules = function(metadata)
  rules_metadata = metadata
  auth_wildcard_rules = { }
  for idx, meta in ipairs(rules_metadata or { }) do
    local requires_auth = false
    local dns_refs = 0
    if meta.conditions then
      for _, cond in ipairs(meta.conditions) do
        if cond.name == "from_users" or cond.name == "from_userlists" then
          requires_auth = true
        end
        if cond.name == "to_domains" or cond.name == "to_domainlist" then
          dns_refs = dns_refs + 1
        end
      end
    end
    if requires_auth and dns_refs == 0 then
      local rule_id = meta.rule_id or "unknown_" .. tostring(idx)
      auth_wildcard_rules[#auth_wildcard_rules + 1] = rule_id
      log_info(function()
        return {
          action = "auth_wildcard_rule_detected",
          rule_id = rule_id,
          idx = idx
        }
      end)
    end
  end
  return log_info(function()
    return {
      action = "auth_wildcard_rules_loaded",
      count = #auth_wildcard_rules,
      rules = table.concat(auth_wildcard_rules, ", ")
    }
  end)
end
local add_to_wildcard_rules
add_to_wildcard_rules = function(add_fn, key, dest, timeout, corr)
  local any_ok = false
  for _, auth_rule_id in ipairs(auth_wildcard_rules) do
    any_ok = any_ok or add_fn(key, dest, auth_rule_id, timeout, corr)
  end
  return any_ok
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
local _benchmark_ts = ffi.new("timespec_t[1]")
local current_benchmark_ms
current_benchmark_ms = function()
  libc.clock_gettime(CLOCK_MONOTONIC, _benchmark_ts)
  return tonumber(_benchmark_ts[0].tv_sec) * 1000 + math.floor(tonumber(_benchmark_ts[0].tv_nsec) / 1000000)
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
local clamp
clamp = function(value, min_v, max_v)
  if value < min_v then
    return min_v
  end
  if value > max_v then
    return max_v
  end
  return value
end
local rr_timeout
rr_timeout = function(ttl)
  local grace = math.max(0, math.floor(tonumber(ttl_cfg.grace) or 600))
  local min_t = math.max(1, math.floor(tonumber(ttl_cfg.min) or 60))
  local max_t = math.max(min_t, math.floor(tonumber(ttl_cfg.max) or 2592000))
  local rr_ttl = tonumber(ttl) or 0
  rr_ttl = math.floor(rr_ttl)
  if rr_ttl < 0 then
    rr_ttl = 0
  end
  local effective = clamp(rr_ttl + grace, min_t, max_t)
  return tostring(effective) .. "s", effective
end
local patch_modified_dns
patch_modified_dns = function(dns_raw, reason)
  local new_dns = strip_https_rr(dns_raw) or dns_raw
  local payload_modified = new_dns ~= dns_raw
  if payload_modified then
    new_dns = clear_ad_bit(new_dns)
    new_dns = add_ede_modified(new_dns, reason) or new_dns
  end
  return new_dns, payload_modified
end
local handle_response
handle_response = function(qh_ptr, nfad, pkt_id)
  local ts = now()
  drain_ts = ts
  drain_pipe(pipe_rfd, now, drain_on_msg)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local l2 = get_l2(nfad)
  local ip, l4, dns_msg, dns_raw, ip_ihl = parse_packet(raw)
  if not (ip) then
    if l4 == "buffering" then
      return NF_DROP
    end
    return NF_ACCEPT
  end
  local _purge_counter = ((_purge_counter or 0) + 1) % 1000
  if _purge_counter == 0 then
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
  local client_ip = dst_ip
  local resolver_ip = src_ip
  local client_mac = ip_to_mac[client_ip] or "unknown"
  local user = user_for_mac(client_mac, client_ip, auth_cfg.sessions_file or "/tmp/sessions.lua")
  local entry = get_pending_entry(txid, dst_ip, client_port, resolver_ip, now)
  if not (entry) then
    local retry_attempts = 0
    local retry_wait_ms = 0
    entry, retry_attempts, retry_wait_ms = retry_pending_match(txid, dst_ip, client_port, resolver_ip)
    if entry then
      log_info(function()
        return {
          action = "response_matched_after_retry",
          src_ip = src_ip,
          dst_ip = dst_ip,
          txid = string.format("0x%04x", txid),
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
          txid = string.format("0x%04x", txid),
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
  consume(txid, dst_ip, client_port, resolver_ip)
  if runtime_cfg.benchmark and entry and entry.benchmark_ms then
    local delta_ms = current_benchmark_ms() - entry.benchmark_ms
    if delta_ms >= 0 then
      log_info(function()
        return {
          action = "dns_benchmark",
          txid = string.format("0x%04x", txid),
          src_ip = src_ip,
          dst_ip = dst_ip,
          delta_ms = delta_ms,
          refused = entry.refused,
          dnsonly = entry.dnsonly,
          user = user
        }
      end)
    end
  end
  local refused = entry and entry.refused or false
  local dnsonly = entry and entry.dnsonly or false
  local nft_rule_id = (entry and entry.rule_id and #entry.rule_id > 0) and entry.rule_id or "unknown_rule"
  local on_response_cbs = get_rule_on_response(nft_rule_id)
  local resp_ctx = {
    dns_raw = nil,
    modified = false,
    explicit_allow = false,
    skip_nft = false,
    action_label = nil,
    reason = entry and entry.reason or ""
  }
  local ack_corr = string.format("%04x:%s:%d:%s", txid, dst_ip, client_port, resolver_ip)
  if refused then
    local refused_dns = build_blocked_response(dns_msg, dns_raw, entry.reason)
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
      local _list_0 = dns_msg.questions
      for _index_0 = 1, #_list_0 do
        local q = _list_0[_index_0]
        _accum_0[_len_0] = q.name
        _len_0 = _len_0 + 1
      end
      return _accum_0
    end)(), ",")
    log_debug(function()
      return {
        action = "response_refused",
        src_ip = src_ip,
        dst_ip = dst_ip,
        vlan = l2.vlan,
        txid = string.format("0x%04x", txid),
        qnames = qnames,
        client_mac = client_mac,
        user = user
      }
    end)
    local patched_ptr = ffi.cast("const unsigned char*", patched)
    libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr)
    return -1
  end
  resp_ctx.dns_raw = dns_raw
  for _index_0 = 1, #on_response_cbs do
    local cb = on_response_cbs[_index_0]
    cb(resp_ctx)
  end
  dns_raw = resp_ctx.dns_raw
  local payload_modified = resp_ctx.modified
  local inject_nft = resp_ctx.explicit_allow or not resp_ctx.skip_nft
  local answers = parse_answers(dns_msg)
  local client_v4 = nil
  local client_v6 = nil
  local ip_count = 0
  local records_to_add = 0
  local success_any = false
  local no_ipv4_records = { }
  local no_ipv6_records = { }
  if inject_nft and not dnsonly then
    drain_ack()
  end
  for _index_0 = 1, #answers do
    local ans = answers[_index_0]
    if ans.rtype == QTYPE.A then
      client_v4 = client_v4 or (function()
        if ip.version == 4 then
          return client_ip
        else
          return resolve_client_family(client_ip, "ipv4")
        end
      end)()
      if inject_nft then
        if client_v4 then
          records_to_add = records_to_add + 1
          local rr_timeout_str, _ = rr_timeout(ans.ttl)
          local ok = add_ip4(client_v4, ans.rdata_str, nft_rule_id, rr_timeout_str, ack_corr)
          if ok then
            ip_count = ip_count + 1
          end
          success_any = success_any or ok
          if user and #auth_wildcard_rules > 0 then
            success_any = success_any or add_to_wildcard_rules(add_ip4, client_v4, ans.rdata_str, rr_timeout_str, ack_corr)
          end
        else
          no_ipv4_records[#no_ipv4_records + 1] = ans.rdata_str
        end
        if mac_valid(client_mac) then
          local rr_timeout_str, _ = rr_timeout(ans.ttl)
          local m_ok = add_mac4(client_mac, ans.rdata_str, nft_rule_id, rr_timeout_str, ack_corr)
          success_any = success_any or m_ok
          if user and #auth_wildcard_rules > 0 then
            success_any = success_any or add_to_wildcard_rules(add_mac4, client_mac, ans.rdata_str, rr_timeout_str, ack_corr)
          end
        end
      end
    elseif ans.rtype == QTYPE.AAAA then
      client_v6 = client_v6 or (function()
        if ip.version == 6 then
          return client_ip
        else
          return resolve_client_family(client_ip, "ipv6")
        end
      end)()
      if inject_nft then
        if client_v6 then
          records_to_add = records_to_add + 1
          local rr_timeout_str, _ = rr_timeout(ans.ttl)
          local ok = add_ip6(client_v6, ans.rdata_str, nft_rule_id, rr_timeout_str, ack_corr)
          if ok then
            ip_count = ip_count + 1
          end
          success_any = success_any or ok
          if user and #auth_wildcard_rules > 0 then
            success_any = success_any or add_to_wildcard_rules(add_ip6, client_v6, ans.rdata_str, rr_timeout_str, ack_corr)
          end
        else
          no_ipv6_records[#no_ipv6_records + 1] = ans.rdata_str
        end
        if mac_valid(client_mac) then
          local rr_timeout_str, _ = rr_timeout(ans.ttl)
          local m_ok = add_mac6(client_mac, ans.rdata_str, nft_rule_id, rr_timeout_str, ack_corr)
          success_any = success_any or m_ok
          if user and #auth_wildcard_rules > 0 then
            success_any = success_any or add_to_wildcard_rules(add_mac6, client_mac, ans.rdata_str, rr_timeout_str, ack_corr)
          end
        end
      end
    end
  end
  if #no_ipv4_records > 0 then
    local log_fn
    if mac_valid(client_mac) then
      log_fn = log_info
    else
      log_fn = log_warn
    end
    log_fn(function()
      return {
        action = "no_ipv4_for_client",
        client = client_ip,
        count = #no_ipv4_records,
        records = table.concat(no_ipv4_records, " "),
        reason = "client_ipv4_unknown",
        mac_fallback = mac_valid(client_mac),
        user = user
      }
    end)
  end
  if #no_ipv6_records > 0 then
    local log_fn
    if mac_valid(client_mac) then
      log_fn = log_info
    else
      log_fn = log_warn
    end
    log_fn(function()
      return {
        action = "no_ipv6_for_client",
        client = client_ip,
        count = #no_ipv6_records,
        records = table.concat(no_ipv6_records, " "),
        reason = "client_ipv6_unknown",
        mac_fallback = mac_valid(client_mac),
        user = user
      }
    end)
  end
  local new_dns, dns_modified = patch_modified_dns(dns_raw, entry.reason)
  payload_modified = payload_modified or dns_modified
  local patched = nil
  if payload_modified then
    patched = replace_dns_payload(raw, ip, l4, ip_ihl, new_dns)
    if not (patched) then
      return NF_DROP
    end
  end
  local qnames = table.concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    local _list_0 = dns_msg.questions
    for _index_0 = 1, #_list_0 do
      local q = _list_0[_index_0]
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
      vlan = l2.vlan,
      txid = string.format("0x%04x", txid),
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
          txid = string.format("0x%04x", txid),
          client_ip = client_ip,
          qnames = qnames,
          user = user
        }
      end)
      return NF_DROP
    else
      log_warn(function()
        return {
          action = "nft_add_failed_fail_open",
          txid = string.format("0x%04x", txid),
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
      wait_ack(pending_seq, ack_corr)
    end
  end
  if not (payload_modified) then
    return NF_ACCEPT
  end
  local patched_ptr = ffi.cast("const unsigned char*", patched)
  libnfq.nfq_set_verdict(qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr)
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
  return run_queue(tonumber(queue_num), handle_response)
end
return {
  run = run,
  rr_timeout = rr_timeout,
  patch_modified_dns = patch_modified_dns
}
