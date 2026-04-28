print("=== Debug AEAD Test ===")
local sp, su
do
  local _obj_0 = string
  sp, su = _obj_0.pack, _obj_0.unpack
end
local band, bor, bnot, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, lshift, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.lshift, _obj_0.rshift
end
local test_data = "test"
print("Test data: " .. tostring(test_data))
print("Length: " .. tostring(#test_data))
for i = 1, #test_data do
  local byte_val = su("B", test_data, i)
  print("Byte " .. tostring(i) .. ": " .. tostring(byte_val) .. " (" .. tostring(string.char(byte_val)) .. ")")
end
print("String unpack test passed")
local val_a = 65
local val_b = 66
local val_c = band(bor(val_a, val_b), bnot(band(val_a, val_b)))
print("XOR test: " .. tostring(val_a) .. " ~ " .. tostring(val_b) .. " = " .. tostring(val_c))
local aead = require("ipparse.lib.crypto.aead")
print("AEAD module loaded successfully")
local iv = string.rep("\0", 12)
local packet_number = 1
print("Testing nonce construction...")
local nonce = aead.construct_nonce(iv, packet_number)
print("Nonce constructed successfully, length: " .. tostring(#nonce))
return print("Debug test complete!")
