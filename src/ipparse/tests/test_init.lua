local util = require("ipparse.lib.util")
local test
test = util.test
local bin2hex, hex2bin, filterascii, hexdump
do
  local _obj_0 = require("ipparse.init")
  bin2hex, hex2bin, filterascii, hexdump = _obj_0.bin2hex, _obj_0.hex2bin, _obj_0.filterascii, _obj_0.hexdump
end
test("hex2bin converts hex to bytes", function()
  local result = hex2bin("ff00")
  return assert(result == "\xff\x00", "hex2bin failed")
end)
test("hex2bin single byte", function()
  local result = hex2bin("ab")
  return assert(result == "\xab", "hex2bin single byte failed")
end)
test("filterascii replaces non-printable with dot", function()
  local result = filterascii("\x01hello\xff")
  return assert(result == ".hello.", "expected '.hello.', got '" .. tostring(result) .. "'")
end)
test("filterascii keeps printable chars", function()
  local result = filterascii("hello")
  return assert(result == "hello", "expected 'hello', got '" .. tostring(result) .. "'")
end)
return util.summary("init")
