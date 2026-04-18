local l7_quic = require("ipparse.l7.quic")
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
print("🧪 Testing QUIC L7 SNI Extraction")
print("")
local create_client_hello_with_sni
create_client_hello_with_sni = function(hostname)
  local sni_name_list = sp(">H", #hostname + 3) .. string.char(0x00) .. sp(">H", #hostname) .. hostname
  local sni_extension = sp(">H", 0x0000) .. sp(">H", #sni_name_list) .. sni_name_list
  local extensions_data = sp(">H", #sni_extension) .. sni_extension
  local client_hello = ""
  client_hello = client_hello .. sp(">H", 0x0303)
  client_hello = client_hello .. string.rep("\x00", 32)
  client_hello = client_hello .. string.char(0x00)
  client_hello = client_hello .. (sp(">H", 2) .. sp(">H", 0x1301))
  client_hello = client_hello .. string.char(0x01, 0x00)
  client_hello = client_hello .. extensions_data
  local handshake_length = #client_hello
  local handshake_msg = string.char(0x01)
  handshake_msg = handshake_msg .. string.char(0x00, (handshake_length >> 8) & 0xFF, handshake_length & 0xFF)
  handshake_msg = handshake_msg .. client_hello
  return handshake_msg
end
local test_l7_parser
test_l7_parser = function(hostname)
  print("=== Testing L7 parser with: " .. tostring(hostname) .. " ===")
  local client_hello_data = create_client_hello_with_sni(hostname)
  local client_hello_msg = {
    type = 1,
    name = "ClientHello",
    data = client_hello_data:sub(5),
    length = #client_hello_data - 4
  }
  print("Created ClientHello message:")
  print("  Type: " .. tostring(client_hello_msg.type))
  print("  Name: " .. tostring(client_hello_msg.name))
  print("  Data length: " .. tostring(client_hello_msg.length))
  print("")
  local parser = l7_quic.QuicL7Parser()
  local sni = parser:extract_sni_from_client_hello(client_hello_msg)
  if sni then
    print("  ✅ SUCCESS: Extracted SNI '" .. tostring(sni) .. "'")
    if sni == hostname then
      print("  ✅ SNI matches expected hostname!")
      return true
    else
      print("  ❌ SNI mismatch: expected '" .. tostring(hostname) .. "'")
    end
  else
    print("  ❌ FAILED: No SNI extracted")
  end
  print("")
  return false
end
local test_cases = {
  "google.com",
  "example.org",
  "github.com"
}
local successes = 0
for _index_0 = 1, #test_cases do
  local hostname = test_cases[_index_0]
  if test_l7_parser(hostname) then
    successes = successes + 1
  end
end
print("🏁 Results: " .. tostring(successes) .. "/" .. tostring(#test_cases) .. " successful")
if successes == #test_cases then
  return print("🎉 SUCCESS: QUIC L7 SNI extraction is working!")
else
  return print("❌ FAILURE: QUIC L7 SNI extraction needs more debugging")
end
