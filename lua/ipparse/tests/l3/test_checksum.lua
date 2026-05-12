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
  local result = checksum("\xff\xff")
  return assert(result == 0, "checksum(0xffff) should be 0, got " .. tostring(result))
end)
test("checksum of 0x0000 is 0xffff", function()
  local result = checksum("\x00\x00")
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
  local result = checksum("\xff")
  return assert(result == 0x00ff, "checksum(\\xff) should be 0x00ff, got " .. tostring(result))
end)
test("checksum6 matches IPv6 pseudo-header formula", function()
  local src = string.char(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
  local dst = string.char(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)
  local payload = "abcdef"
  local got = checksum6(src, dst, 17, payload)
  local expected = checksum(sp(">c16c16 I4 xxx B c" .. tostring(#payload), src, dst, #payload, 17, payload))
  return assert(got == expected, "checksum6 mismatch: got " .. tostring(got) .. ", expected " .. tostring(expected))
end)
return util.summary("l3/checksum")
