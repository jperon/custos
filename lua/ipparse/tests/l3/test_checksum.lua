local util = require("ipparse.lib.util")
local test
test = util.test
local sp
sp = require("ipparse.lib.pack_compat").pack
local checksum, checksum6
do
  local _obj_0 = require("ipparse.l3.lib")
  checksum, checksum6 = _obj_0.checksum, _obj_0.checksum6
end
local ip4 = require("ipparse.l3.ip4")
test("checksum of 0xffff is 0", function()
  local result = checksum("\255\255")
  return assert(result == 0, "checksum(0xffff) should be 0, got " .. tostring(result))
end)
test("checksum of 0x0000 is 0xffff", function()
  local result = checksum("\000\000")
  return assert(result == 0xffff, "checksum(0x0000) should be 0xffff, got " .. tostring(result))
end)
test("checksum of packed header is 0", function()
  local hdr = ip4.new({
    src = ip4.s2ip4("192.168.1.1"),
    dst = ip4.s2ip4("192.168.1.2"),
    protocol = 6,
    options = ""
  })
  local raw = tostring(hdr)
  local header_bytes = raw:sub(1, 20)
  local result = checksum(header_bytes)
  return assert(result == 0, "checksum of valid IP header should be 0, got " .. tostring(result))
end)
test("checksum odd-length pads with zero", function()
  local result = checksum("\255")
  return assert(result == 0x00ff, "checksum(\\255) should be 0x00ff, got " .. tostring(result))
end)
test("checksum6 matches IPv6 pseudo-header formula", function()
  local src = string.char(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
  local dst = string.char(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)
  local payload = "abcdef"
  local got = checksum6(src, dst, 17, payload)
  local expected = checksum(sp(">c16c16 I4 xxx B c" .. tostring(#payload), src, dst, #payload, 17, payload))
  return assert(got == expected, "checksum6 mismatch: got " .. tostring(got) .. ", expected " .. tostring(expected))
end)
test("checksum6 stable across payload lengths (frozen values)", function()
  local src = string.char(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
  local dst = string.char(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)
  assert(checksum6(src, dst, 17, "abcdef") == 31302, "checksum6 (6 bytes) changed")
  assert(checksum6(src, dst, 17, "hello world!!") == 61820, "checksum6 (13 bytes) changed")
  return assert(checksum6(src, dst, 17, "xyz") == 45564, "checksum6 (3 bytes, odd) changed")
end)
local ref_checksum
ref_checksum = function(s)
  if #s % 2 == 1 then
    s = s .. "\0"
  end
  local cksm = 0
  for i = 1, #s, 2 do
    local a, b = string.byte(s, i, i + 1)
    cksm = cksm + (a * 256 + b)
  end
  while true do
    local carry = math.floor(cksm / 0x10000)
    if carry == 0 then
      break
    end
    cksm = (cksm % 0x10000) + carry
  end
  return 0xFFFF - (cksm % 0x10000)
end
local _pattern_parts = { }
for i = 0, 255 do
  _pattern_parts[#_pattern_parts + 1] = string.char(i)
end
local PATTERN = table.concat(_pattern_parts)
test("checksum matches the RFC 1071 reference on rotated buffers", function()
  for len = 1, 67 do
    local rot = (len * 7) % 256 + 1
    local buf = (PATTERN .. PATTERN):sub(rot, rot + len - 1)
    local got, want = checksum(buf), ref_checksum(buf)
    assert(got == want, "checksum len=" .. tostring(len) .. ": got " .. tostring(got) .. ", reference " .. tostring(want))
  end
  local big = (string.rep(PATTERN, 16)):sub(1, 4000)
  return assert(checksum(big) == ref_checksum(big), "checksum on 4000-byte buffer changed")
end)
test("checksum of a DNS-over-UDP payload is stable (frozen value)", function()
  local payload = string.char(0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01)
  assert(checksum(payload) == ref_checksum(payload), "DNS payload checksum changed")
  return assert(checksum(payload) == 0x9ddc, "DNS payload checksum frozen value changed")
end)
return util.summary("l3/checksum")
