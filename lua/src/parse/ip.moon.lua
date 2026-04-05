local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local PROTO_UDP, AF_INET, AF_INET6
do
  local _obj_0 = require("config")
  PROTO_UDP, AF_INET, AF_INET6 = _obj_0.PROTO_UDP, _obj_0.AF_INET, _obj_0.AF_INET6
end
local bit = require("bit")
local read_u8
read_u8 = function(s, i)
  return s:byte(i)
end
local read_u16
read_u16 = function(s, i)
  return bit.bor(bit.lshift(s:byte(i), 8), s:byte(i + 1))
end
local read_u32
read_u32 = function(s, i)
  return tonumber(ffi.new("uint32_t", bit.bor(bit.lshift(s:byte(i), 24), bit.lshift(s:byte(i + 1), 16), bit.lshift(s:byte(i + 2), 8), s:byte(i + 3))))
end
local format_ipv4
format_ipv4 = function(s, i)
  return tostring(s:byte(i)) .. "." .. tostring(s:byte(i + 1)) .. "." .. tostring(s:byte(i + 2)) .. "." .. tostring(s:byte(i + 3))
end
local format_ipv6
format_ipv6 = function(s, i)
  local groups
  do
    local _accum_0 = { }
    local _len_0 = 1
    for g = 0, 7 do
      _accum_0[_len_0] = string.format("%x", read_u16(s, i + g * 2))
      _len_0 = _len_0 + 1
    end
    groups = _accum_0
  end
  return table.concat(groups, ":")
end
local parse_ipv4
parse_ipv4 = function(raw)
  if #raw < 20 then
    return nil
  end
  local version = bit.rshift(bit.band(read_u8(raw, 1), 0xF0), 4)
  if version ~= 4 then
    return nil
  end
  local ihl = bit.band(read_u8(raw, 1), 0x0F) * 4
  local total_len = read_u16(raw, 3)
  local protocol = read_u8(raw, 10)
  if #raw < ihl then
    return nil
  end
  local src_ip = format_ipv4(raw, 13)
  local dst_ip = format_ipv4(raw, 17)
  local src_ip_raw = raw:sub(13, 16)
  local dst_ip_raw = raw:sub(17, 20)
  return {
    version = 4,
    ihl = ihl,
    total_len = total_len,
    protocol = protocol,
    src_ip = src_ip,
    dst_ip = dst_ip,
    src_ip_raw = src_ip_raw,
    dst_ip_raw = dst_ip_raw,
    af = AF_INET
  }
end
local checksum_ip
checksum_ip = function(raw_header)
  local sum = 0
  local i = 1
  while i < #raw_header do
    sum = sum + read_u16(raw_header, i)
    i = i + 2
  end
  while sum > 0xFFFF do
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  end
  return bit.band(bit.bnot(sum), 0xFFFF)
end
local parse_ipv6
parse_ipv6 = function(raw)
  if #raw < 40 then
    return nil
  end
  local version = bit.rshift(bit.band(read_u8(raw, 1), 0xF0), 4)
  if version ~= 6 then
    return nil
  end
  local next_header = read_u8(raw, 7)
  if next_header ~= PROTO_UDP then
    return nil
  end
  local src_ip = format_ipv6(raw, 9)
  local dst_ip = format_ipv6(raw, 25)
  local src_ip_raw = raw:sub(9, 24)
  local dst_ip_raw = raw:sub(25, 40)
  return {
    version = 6,
    ihl = 40,
    protocol = next_header,
    src_ip = src_ip,
    dst_ip = dst_ip,
    src_ip_raw = src_ip_raw,
    dst_ip_raw = dst_ip_raw,
    af = AF_INET6
  }
end
local parse_ip
parse_ip = function(raw)
  if #raw < 1 then
    return nil
  end
  local version = bit.rshift(bit.band(read_u8(raw, 1), 0xF0), 4)
  local _exp_0 = version
  if 4 == _exp_0 then
    return parse_ipv4(raw)
  elseif 6 == _exp_0 then
    return parse_ipv6(raw)
  else
    return nil
  end
end
return {
  parse_ip = parse_ip,
  parse_ipv4 = parse_ipv4,
  parse_ipv6 = parse_ipv6,
  checksum_ip = checksum_ip,
  format_ipv4 = format_ipv4,
  format_ipv6 = format_ipv6,
  read_u8 = read_u8,
  read_u16 = read_u16,
  read_u32 = read_u32
}
