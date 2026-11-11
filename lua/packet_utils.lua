local ffi
ffi = require("ffi_defs").ffi
local new_stream
new_stream = require("ipparse.l4.tcp_stream").new
local parse_ip4, parse_ip6, parse_udp, parse_tcp, parse_dns
do
  local _obj_0 = require("lib.packet_parsing")
  parse_ip4, parse_ip6, parse_udp, parse_tcp, parse_dns = _obj_0.parse_ip4, _obj_0.parse_ip6, _obj_0.parse_udp, _obj_0.parse_tcp, _obj_0.parse_dns
end
local PROTO_UDP, PROTO_TCP
do
  local _obj_0 = require("lib.checksums")
  PROTO_UDP, PROTO_TCP = _obj_0.PROTO_UDP, _obj_0.PROTO_TCP
end
local bit = require("bit")
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
local mac2s
mac2s = function(s, off)
  if off == nil then
    off = 1
  end
  return string.format("%02x:%02x:%02x:%02x:%02x:%02x", s:byte(off), s:byte(off + 1), s:byte(off + 2), s:byte(off + 3), s:byte(off + 4), s:byte(off + 5))
end
local dns_tcp_complete
dns_tcp_complete = function(buf)
  if #buf < 2 then
    return false
  end
  return #buf >= 2 + buf:byte(1) * 256 + buf:byte(2)
end
local new_dns_tcp_stream
new_dns_tcp_stream = function(check_complete)
  if check_complete == nil then
    check_complete = dns_tcp_complete
  end
  return new_stream(check_complete)
end
local parse_dns_packet
parse_dns_packet = function(raw, tcp_state)
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
return {
  skip_ipv6_ext_hdrs = skip_ipv6_ext_hdrs,
  mac2s = mac2s,
  dns_tcp_complete = dns_tcp_complete,
  new_dns_tcp_stream = new_dns_tcp_stream,
  parse_dns_packet = parse_dns_packet
}
