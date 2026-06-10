local bit = require("bit")
local PROTO_UDP = 17
local PROTO_TCP = 6
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
local fold16
fold16 = function(sum)
  while bit.rshift(sum, 16) ~= 0 do
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  end
  return sum
end
local fix_ip4_cksum
fix_ip4_cksum = function(buf, ihl)
  buf[10] = 0
  buf[11] = 0
  local sum = 0
  for i = 0, ihl - 1, 2 do
    sum = sum + bit.bor(bit.lshift(buf[i], 8), buf[i + 1])
  end
  return w16(buf, 10, bit.band(bit.bnot(fold16(sum)), 0xFFFF))
end
local PH_FIRST = {
  [4] = 12,
  [6] = 8
}
local PH_LAST = {
  [4] = 18,
  [6] = 38
}
local fix_l4_cksum
fix_l4_cksum = function(buf, pkt_len, l4_off, version, proto)
  local is_udp = proto == PROTO_UDP
  if pkt_len < l4_off + (is_udp and 8 or 20) then
    return 
  end
  local l4_len = is_udp and r16(buf, l4_off + 4) or pkt_len - l4_off
  local cksum_off = l4_off + (is_udp and 6 or 16)
  buf[cksum_off] = 0
  buf[cksum_off + 1] = 0
  local sum = 0
  for i = PH_FIRST[version], PH_LAST[version], 2 do
    sum = sum + r16(buf, i)
  end
  sum = sum + proto
  sum = sum + l4_len
  local l4_end = l4_off + l4_len
  if l4_end > pkt_len then
    l4_end = pkt_len
  end
  local i = l4_off
  while i < l4_end do
    local word
    if i == cksum_off then
      word = 0
    elseif i + 1 < l4_end then
      word = r16(buf, i)
    else
      word = bit.lshift(buf[i], 8)
    end
    sum = sum + word
    i = i + 2
  end
  local cksum = bit.band(bit.bnot(fold16(sum)), 0xFFFF)
  if cksum == 0 then
    cksum = 0xFFFF
  end
  return w16(buf, cksum_off, cksum)
end
return {
  r16 = r16,
  w16 = w16,
  w32 = w32,
  fold16 = fold16,
  fix_ip4_cksum = fix_ip4_cksum,
  fix_l4_cksum = fix_l4_cksum,
  PROTO_UDP = PROTO_UDP,
  PROTO_TCP = PROTO_TCP
}
