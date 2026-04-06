local ffi, ndpi_lib, major
do
  local _obj_0 = require("ffi_ndpi")
  ffi, ndpi_lib, major = _obj_0.ffi, _obj_0.ndpi_lib, _obj_0.major
end
local AF_INET, AF_INET6
do
  local _obj_0 = require("config")
  AF_INET, AF_INET6 = _obj_0.AF_INET, _obj_0.AF_INET6
end
local bit = require("bit")
local backend
if major >= 5 then
  backend = require("parse.ndpi_v5")
else
  backend = require("parse.ndpi_v4")
end
local PROTO_UDP = 17
local QTYPE = {
  A = 1,
  NS = 2,
  CNAME = 5,
  SOA = 6,
  MX = 15,
  TXT = 16,
  AAAA = 28,
  SRV = 33,
  ANY = 255
}
local QTYPE_NAME = { }
for k, v in pairs(QTYPE) do
  QTYPE_NAME[v] = k
end
local RCODE = {
  NOERROR = 0,
  FORMERR = 1,
  SERVFAIL = 2,
  NXDOMAIN = 3,
  REFUSED = 5
}
local NDPI_PROTOCOL_DNS = 5
local ipv6_str = ffi.new("char[46]")
local r16
r16 = function(p, o)
  return bit.bor(bit.lshift(p[o], 8), p[o + 1])
end
local r32
r32 = function(p, o)
  return tonumber(ffi.cast("uint32_t", bit.bor(bit.lshift(p[o], 24), bit.lshift(p[o + 1], 16), bit.lshift(p[o + 2], 8), p[o + 3])))
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
local fmt_ipv4
fmt_ipv4 = function(p, o)
  return string.format("%d.%d.%d.%d", p[o], p[o + 1], p[o + 2], p[o + 3])
end
local fmt_ipv6
fmt_ipv6 = function(p, o)
  ffi.C.inet_ntop(AF_INET6, p + o, ipv6_str, 46)
  return ffi.string(ipv6_str)
end
local decode_name
decode_name = function(dns, len, off)
  local labels = { }
  local pos = off
  local consumed = 0
  local jumped = false
  local safety = 0
  while pos < len do
    safety = safety + 1
    if safety > 128 then
      return nil, 0
    end
    local label_len = dns[pos]
    if label_len == 0 then
      if not (jumped) then
        consumed = consumed + 1
      end
      break
    elseif bit.band(label_len, 0xC0) == 0xC0 then
      if pos + 1 >= len then
        return nil, 0
      end
      local ptr = bit.bor(bit.lshift(bit.band(label_len, 0x3F), 8), dns[pos + 1])
      if not (jumped) then
        consumed = consumed + 2
      end
      jumped = true
      pos = ptr
    else
      if pos + 1 + label_len > len then
        return nil, 0
      end
      labels[#labels + 1] = ffi.string(dns + pos + 1, label_len)
      pos = pos + (1 + label_len)
      if not (jumped) then
        consumed = consumed + (1 + label_len)
      end
    end
  end
  return table.concat(labels, "."), consumed
end
local parse_l3_v4
parse_l3_v4 = function(p, len)
  if len < 20 then
    return nil
  end
  local ver = bit.rshift(p[0], 4)
  if ver ~= 4 then
    return nil
  end
  local ihl = bit.band(p[0], 0x0F) * 4
  if len < ihl then
    return nil
  end
  return {
    version = 4,
    ihl = ihl,
    total_len = r16(p, 2),
    protocol = p[9],
    src_ip = fmt_ipv4(p, 12),
    dst_ip = fmt_ipv4(p, 16),
    src_ip_raw = ffi.string(p + 12, 4),
    dst_ip_raw = ffi.string(p + 16, 4),
    af = AF_INET
  }
end
local parse_l3_v6
parse_l3_v6 = function(p, len)
  if len < 40 then
    return nil
  end
  local ver = bit.rshift(p[0], 4)
  if ver ~= 6 then
    return nil
  end
  return {
    version = 6,
    ihl = 40,
    total_len = 40 + r16(p, 4),
    protocol = p[6],
    src_ip = fmt_ipv6(p, 8),
    dst_ip = fmt_ipv6(p, 24),
    src_ip_raw = ffi.string(p + 8, 16),
    dst_ip_raw = ffi.string(p + 24, 16),
    af = AF_INET6
  }
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
  local cksum = bit.band(bit.bnot(sum), 0xFFFF)
  return w16(buf, 10, cksum)
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
fix_udp6_cksum = function(buf, pkt_len)
  local udp_off = 40
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
local parse_packet
parse_packet = function(raw)
  local len = #raw
  if len < 20 then
    return nil
  end
  local p = ffi.cast("const uint8_t*", raw)
  local ver = bit.rshift(p[0], 4)
  local ip
  if ver == 4 then
    ip = parse_l3_v4(p, len)
  elseif ver == 6 then
    ip = parse_l3_v6(p, len)
  end
  if not (ip) then
    return nil
  end
  if ip.protocol ~= PROTO_UDP then
    return nil
  end
  local udp_off = ip.ihl
  if len < udp_off + 8 then
    return nil
  end
  local udp = {
    src_port = r16(p, udp_off),
    dst_port = r16(p, udp_off + 2),
    udp_len = r16(p, udp_off + 4),
    udp_off = udp_off,
    payload_off = udp_off + 8,
    payload_len = len - udp_off - 8
  }
  local dns_off = udp.payload_off
  local dns_len = udp.payload_len
  if dns_len < 12 then
    return nil
  end
  local dns_p = p + dns_off
  local flags_hi = dns_p[2]
  local flags_lo = dns_p[3]
  local dns = {
    txid = r16(dns_p, 0),
    is_response = bit.band(flags_hi, 0x80) ~= 0,
    opcode = bit.band(bit.rshift(flags_hi, 3), 0x0F),
    aa = bit.band(flags_hi, 0x04) ~= 0,
    tc = bit.band(flags_hi, 0x02) ~= 0,
    rd = bit.band(flags_hi, 0x01) ~= 0,
    ra = bit.band(flags_lo, 0x80) ~= 0,
    rcode = bit.band(flags_lo, 0x0F),
    qdcount = r16(dns_p, 4),
    ancount = r16(dns_p, 6),
    nscount = r16(dns_p, 8),
    arcount = r16(dns_p, 10)
  }
  local questions = { }
  local qpos = 12
  for _ = 1, dns.qdcount do
    if qpos >= dns_len then
      break
    end
    local qname, consumed = decode_name(dns_p, dns_len, qpos)
    if not (qname) then
      break
    end
    qpos = qpos + consumed
    if qpos + 4 > dns_len then
      break
    end
    local qtype = r16(dns_p, qpos)
    local qclass = r16(dns_p, qpos + 2)
    qpos = qpos + 4
    questions[#questions + 1] = {
      qname = qname,
      qtype = qtype,
      qclass = qclass,
      qtype_name = QTYPE_NAME[qtype] or "TYPE" .. tostring(qtype)
    }
  end
  local answers_off = qpos
  local ndpi_master, ndpi_app = backend.detect(p, len)
  return {
    ip = ip,
    udp = udp,
    dns = dns,
    questions = questions,
    answers_off = answers_off,
    ndpi_master = ndpi_master,
    ndpi_app = ndpi_app
  }
end
local parse_answers
parse_answers = function(raw, pkt)
  if not (pkt.dns.is_response and pkt.dns.ancount > 0) then
    return { }
  end
  local p = ffi.cast("const uint8_t*", raw)
  local dns_p = p + pkt.udp.payload_off
  local dns_len = pkt.udp.payload_len
  local pos = pkt.answers_off
  local answers = { }
  for _ = 1, pkt.dns.ancount do
    if pos >= dns_len then
      break
    end
    local name, consumed = decode_name(dns_p, dns_len, pos)
    if not (name) then
      break
    end
    pos = pos + consumed
    if pos + 10 > dns_len then
      break
    end
    local rtype = r16(dns_p, pos)
    local rclass = r16(dns_p, pos + 2)
    local ttl = r32(dns_p, pos + 4)
    local ttl_off = pos + 4
    local rdlength = r16(dns_p, pos + 8)
    pos = pos + 10
    if pos + rdlength > dns_len then
      break
    end
    local rdata_str
    if rtype == QTYPE.A and rdlength == 4 then
      rdata_str = fmt_ipv4(dns_p, pos)
    elseif rtype == QTYPE.AAAA and rdlength == 16 then
      rdata_str = fmt_ipv6(dns_p, pos)
    elseif rtype == QTYPE.CNAME then
      local cname
      cname, _ = decode_name(dns_p, dns_len, pos)
      rdata_str = cname or "?"
    else
      rdata_str = "(rdata " .. tostring(rdlength) .. "B)"
    end
    local rdata_raw_len
    if rtype == QTYPE.A then
      rdata_raw_len = 4
    elseif rtype == QTYPE.AAAA then
      rdata_raw_len = 16
    else
      rdata_raw_len = 0
    end
    local rdata_raw
    if rdata_raw_len > 0 then
      rdata_raw = ffi.string(dns_p + pos, rdata_raw_len)
    else
      rdata_raw = ""
    end
    answers[#answers + 1] = {
      name = name,
      rtype = rtype,
      rclass = rclass,
      ttl = ttl,
      rdlength = rdlength,
      rdata_str = rdata_str,
      rdata_raw = rdata_raw,
      rtype_name = QTYPE_NAME[rtype] or "TYPE" .. tostring(rtype),
      ttl_offset = ttl_off
    }
    pos = pos + rdlength
  end
  return answers
end
local patch_and_checksum
patch_and_checksum = function(raw, pkt, answers, new_ttl)
  local pkt_len = #raw
  local buf = ffi.new("uint8_t[?]", pkt_len)
  ffi.copy(buf, raw, pkt_len)
  local dns_off = pkt.udp.payload_off
  for _index_0 = 1, #answers do
    local ans = answers[_index_0]
    w32(buf, dns_off + ans.ttl_offset, new_ttl)
  end
  if pkt.ip.version == 4 then
    fix_udp4_cksum(buf, pkt_len, pkt.ip.ihl)
    fix_ip4_cksum(buf, pkt.ip.ihl)
  elseif pkt.ip.version == 6 then
    fix_udp6_cksum(buf, pkt_len)
  end
  return ffi.string(buf, pkt_len)
end
local cleanup
cleanup = function()
  return backend.cleanup()
end
local warmup
warmup = function()
  local dummy = ffi.new("uint8_t[28]")
  ffi.fill(dummy, 28, 0)
  dummy[0] = 0x45
  dummy[9] = 17
  backend.detect(dummy, 28)
  return nil
end
return {
  parse_packet = parse_packet,
  parse_answers = parse_answers,
  patch_and_checksum = patch_and_checksum,
  cleanup = cleanup,
  warmup = warmup,
  QTYPE = QTYPE,
  QTYPE_NAME = QTYPE_NAME,
  RCODE = RCODE
}
