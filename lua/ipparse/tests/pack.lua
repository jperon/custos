local test
test = require("lib.util").test
local pack, unpack
do
  local _obj_0 = require("lib.pack_compat")
  pack, unpack = _obj_0.pack, _obj_0.unpack
end
local concat
concat = table.concat
test("PACK pack / unpack B", function()
  local packed = pack("B", 35)
  local result, new_offset = unpack("B", packed)
  assert(result == 35)
  return assert(new_offset == 2)
end)
test("PACK pack / unpack I", function()
  local packed = pack("I", 35)
  local result, new_offset = unpack("I", packed)
  assert(result == 35)
  return assert(new_offset == 5)
end)
return test("PACK pack / unpack s2", function()
  local test_str = "he"
  local packed = pack("s2", test_str)
  local result, new_offset = unpack("s2", packed)
  assert(result == test_str)
  return assert(new_offset == 2 * #test_str + 1, "OFFSET: " .. tostring(new_offset) .. ", EXPECTED: " .. tostring(2 * #test_str + 1))
end)
