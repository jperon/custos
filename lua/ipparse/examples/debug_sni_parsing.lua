local bin2hex, hex2bin
do
  local _obj_0 = require("ipparse.init")
  bin2hex, hex2bin = _obj_0.bin2hex, _obj_0.hex2bin
end
local sp, su
do
  local _obj_0 = string
  sp, su = _obj_0.pack, _obj_0.unpack
end
print("🔍 Debugging SNI Parsing Issue")
print("")
local test_sni_parsing
test_sni_parsing = function(hostname)
  print("=== Testing SNI parsing for: " .. tostring(hostname) .. " ===")
  local sni_name_list = sp(">H", #hostname + 3) .. string.char(0x00) .. sp(">H", #hostname) .. hostname
  print("Created SNI extension data:")
  print("  Hostname: " .. tostring(hostname))
  print("  Hostname length: " .. tostring(#hostname))
  print("  SNI data length: " .. tostring(#sni_name_list))
  print("  SNI data hex: " .. tostring(bin2hex(sni_name_list)))
  print("")
  print("Manual parsing:")
  local offset = 1
  local list_len = su(">H", sni_name_list, offset)
  offset = offset + 2
  print("  Server name list length: " .. tostring(list_len) .. " (should be " .. tostring(#hostname + 3) .. ")")
  local name_type = su("B", sni_name_list, offset)
  offset = offset + 1
  print("  Name type: " .. tostring(name_type) .. " (should be 0)")
  local name_len = su(">H", sni_name_list, offset)
  offset = offset + 2
  print("  Name length: " .. tostring(name_len) .. " (should be " .. tostring(#hostname) .. ")")
  print("  Data available from offset " .. tostring(offset) .. ": " .. tostring(#sni_name_list - offset + 1) .. " bytes")
  print("  Need " .. tostring(name_len) .. " bytes")
  if offset + name_len - 1 <= #sni_name_list then
    local extracted = sni_name_list:sub(offset, offset + name_len - 1)
    print("  ✅ Extracted hostname: '" .. tostring(extracted) .. "'")
    if extracted == hostname then
      print("  ✅ SUCCESS!")
      return true
    else
      print("  ❌ Mismatch!")
    end
  else
    print("  ❌ Not enough data!")
  end
  print("")
  return false
end
local test_cases = {
  "google.com",
  "example.org",
  "a.com"
}
local successes = 0
for _index_0 = 1, #test_cases do
  local hostname = test_cases[_index_0]
  if test_sni_parsing(hostname) then
    successes = successes + 1
  end
end
return print("Results: " .. tostring(successes) .. "/" .. tostring(#test_cases) .. " successful")
