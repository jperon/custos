local ffi = require("ffi")
local bit = require("bit")
local w16, w32, fix_ip4_cksum, fix_l4_cksum, PROTO_UDP, PROTO_TCP
do
  local _obj_0 = require("lib.checksums")
  w16, w32, fix_ip4_cksum, fix_l4_cksum, PROTO_UDP, PROTO_TCP = _obj_0.w16, _obj_0.w32, _obj_0.fix_ip4_cksum, _obj_0.fix_l4_cksum, _obj_0.PROTO_UDP, _obj_0.PROTO_TCP
end
local ip2s, QTYPE
do
  local _obj_0 = require("lib.packet_parsing")
  ip2s, QTYPE = _obj_0.ip2s, _obj_0.dns_types
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
    else
      w16(new_buf, 4, (ip_ihl - 40) + udp_len)
    end
    fix_l4_cksum(new_buf, new_pkt_len, ip_ihl, ip.version, PROTO_UDP)
    if ip.version == 4 then
      fix_ip4_cksum(new_buf, ip_ihl)
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
    else
      w16(new_buf, 4, (ip_ihl - 40) + tcp_hdr_len + 2 + dns_len)
    end
    fix_l4_cksum(new_buf, new_pkt_len, ip_ihl, ip.version, PROTO_TCP)
    if ip.version == 4 then
      fix_ip4_cksum(new_buf, ip_ihl)
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
local build_query_from_response
build_query_from_response = function(dns_raw, qdcount)
  if qdcount == nil then
    qdcount = 1
  end
  if not (dns_raw and #dns_raw >= 12) then
    return nil
  end
  if not (qdcount and qdcount >= 1) then
    return nil
  end
  local off = 13
  for _ = 1, qdcount do
    while true do
      if off > #dns_raw then
        return nil
      end
      local len = dns_raw:byte(off)
      off = off + 1
      if len == 0 then
        break
      end
      if bit.band(len, 0xC0) ~= 0 then
        return nil
      end
      off = off + len
    end
    off = off + 4
    if off - 1 > #dns_raw then
      return nil
    end
  end
  local q_end = off - 1
  local b3 = bit.band(bit.bor(dns_raw:byte(3), 0x01), 0x7F)
  local header = string.char(dns_raw:byte(1), dns_raw:byte(2), b3, 0x00, dns_raw:byte(5), dns_raw:byte(6), 0, 0, 0, 0, 0, 0)
  return header .. dns_raw:sub(13, q_end)
end
return {
  replace_dns_payload = replace_dns_payload,
  decode_simple_cname = decode_simple_cname,
  fmt_rdata = fmt_rdata,
  parse_answers = parse_answers,
  build_query_from_response = build_query_from_response
}
