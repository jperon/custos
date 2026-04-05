local read_u16
read_u16 = require("parse/ip").read_u16
local DNS_PORT
DNS_PORT = require("config").DNS_PORT
local UDP_HEADER_LEN = 8
local parse_udp
parse_udp = function(raw, ip_hdr)
  local udp_off = ip_hdr.ihl + 1
  if #raw < udp_off + UDP_HEADER_LEN - 1 then
    return nil
  end
  local src_port = read_u16(raw, udp_off)
  local dst_port = read_u16(raw, udp_off + 2)
  local udp_len = read_u16(raw, udp_off + 4)
  if src_port ~= DNS_PORT and dst_port ~= DNS_PORT then
    return nil
  end
  local payload_off = udp_off + UDP_HEADER_LEN
  return {
    src_port = src_port,
    dst_port = dst_port,
    udp_len = udp_len,
    payload_off = payload_off,
    dns_payload = raw:sub(payload_off),
    udp_off = udp_off
  }
end
local pseudo_header_sum_v4
pseudo_header_sum_v4 = function(src_ip_raw, dst_ip_raw, udp_len)
  local sum = 0
  sum = sum + read_u16(src_ip_raw, 1)
  sum = sum + read_u16(src_ip_raw, 3)
  sum = sum + read_u16(dst_ip_raw, 1)
  sum = sum + read_u16(dst_ip_raw, 3)
  sum = sum + 17
  sum = sum + udp_len
  return sum
end
local checksum_udp
checksum_udp = function(raw, ip_hdr, udp_hdr)
  read_u16 = require("parse/ip").read_u16
  local bit = require("bit")
  local sum = pseudo_header_sum_v4(ip_hdr.src_ip_raw, ip_hdr.dst_ip_raw, udp_hdr.udp_len)
  local udp_start = udp_hdr.udp_off
  local udp_end = udp_start + udp_hdr.udp_len - 1
  local i = udp_start
  local cksum_off = udp_start + 6
  while i <= udp_end do
    local word
    if i == cksum_off then
      word = 0
    elseif i + 1 <= udp_end then
      word = read_u16(raw, i)
    else
      word = bit.lshift(raw:byte(i), 8)
    end
    sum = sum + word
    i = i + 2
  end
  while sum > 0xFFFF do
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  end
  return bit.band(bit.bnot(sum), 0xFFFF)
end
return {
  parse_udp = parse_udp,
  checksum_udp = checksum_udp,
  pseudo_header_sum_v4 = pseudo_header_sum_v4,
  UDP_HEADER_LEN = UDP_HEADER_LEN
}
