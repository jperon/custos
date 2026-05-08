local util = require("ipparse.lib.util")
local test
test = util.test
local checksum
checksum = require("ipparse.l3.lib").checksum
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
return util.summary("l3/checksum")
