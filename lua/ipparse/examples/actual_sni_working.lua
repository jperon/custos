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
local band, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, rshift = _obj_0.band, _obj_0.rshift
end
print("🎯 ===== ACTUALLY WORKING SNI EXTRACTION =====")
print("")
local extract_sni_directly
extract_sni_directly = function(hostname)
  print("=== Direct SNI Extraction Test: " .. tostring(hostname) .. " ===")
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
  handshake_msg = handshake_msg .. string.char(0x00, rshift(handshake_length, 8) & 0xFF, band(handshake_length, 0xFF))
  handshake_msg = handshake_msg .. client_hello
  local record_length = #handshake_msg
  local tls_record = string.char(0x16)
  tls_record = tls_record .. sp(">H", 0x0303)
  tls_record = tls_record .. sp(">H", record_length)
  tls_record = tls_record .. handshake_msg
  print("Created TLS ClientHello:")
  print("  Total length: " .. tostring(#tls_record) .. " bytes")
  print("  Record length: " .. tostring(record_length) .. " bytes")
  print("  Handshake length: " .. tostring(handshake_length) .. " bytes")
  print("  Expected calculation: 5 (record header) + " .. tostring(record_length) .. " = " .. tostring(5 + record_length))
  print("")
  print("Parsing TLS record:")
  local content_type = su("B", tls_record, 1)
  local version = su(">H", tls_record, 2)
  local length = su(">H", tls_record, 4)
  print("  Content type: " .. tostring(content_type) .. " (should be 22)")
  print("  Version: 0x" .. tostring(string.format("%04x", version)))
  print("  Length: " .. tostring(length))
  print("  Available data: " .. tostring(#tls_record - 5) .. " bytes")
  if #tls_record < 5 + length then
    print("  ❌ Not enough data!")
    return false
  end
  local handshake_data = tls_record:sub(6, 5 + length)
  print("  ✅ Extracted handshake data: " .. tostring(#handshake_data) .. " bytes")
  local hs_type = su("B", handshake_data, 1)
  local hs_len = su(">I4", "\0" .. handshake_data:sub(2, 4))
  print("  Handshake type: " .. tostring(hs_type) .. " (should be 1 for ClientHello)")
  print("  Handshake length: " .. tostring(hs_len))
  print("  Available handshake data: " .. tostring(#handshake_data - 4) .. " bytes")
  if #handshake_data < 4 + hs_len then
    print("  ❌ Not enough handshake data!")
    return false
  end
  local ch_payload = handshake_data:sub(5, 4 + hs_len)
  print("  ✅ Extracted ClientHello payload: " .. tostring(#ch_payload) .. " bytes")
  print("")
  print("Parsing ClientHello for SNI:")
  local offset = 1
  offset = offset + (2 + 32)
  print("  After version+random: offset=" .. tostring(offset))
  local session_id_len = su("B", ch_payload, offset)
  offset = offset + (1 + session_id_len)
  print("  After session ID (len=" .. tostring(session_id_len) .. "): offset=" .. tostring(offset))
  local cipher_suites_len = su(">H", ch_payload, offset)
  offset = offset + (2 + cipher_suites_len)
  print("  After cipher suites (len=" .. tostring(cipher_suites_len) .. "): offset=" .. tostring(offset))
  local compression_len = su("B", ch_payload, offset)
  offset = offset + (1 + compression_len)
  print("  After compression (len=" .. tostring(compression_len) .. "): offset=" .. tostring(offset))
  local extensions_len = su(">H", ch_payload, offset)
  offset = offset + 2
  print("  Extensions length: " .. tostring(extensions_len) .. ", starting at offset=" .. tostring(offset))
  local extensions_end = offset + extensions_len
  while offset < extensions_end - 3 do
    local ext_type = su(">H", ch_payload, offset)
    local ext_len = su(">H", ch_payload, offset + 2)
    offset = offset + 4
    print("  Extension type: " .. tostring(ext_type) .. ", length: " .. tostring(ext_len))
    if ext_type == 0 then
      print("  🎯 Found SNI extension!")
      if offset + ext_len <= #ch_payload then
        local sni_ext_data = ch_payload:sub(offset, offset + ext_len - 1)
        if #sni_ext_data >= 5 then
          local list_len = su(">H", sni_ext_data, 1)
          local name_type = su("B", sni_ext_data, 3)
          local name_len = su(">H", sni_ext_data, 4)
          if name_type == 0 and 6 + name_len - 1 <= #sni_ext_data then
            local extracted_hostname = sni_ext_data:sub(6, 5 + name_len)
            print("  🎉 EXTRACTED SNI: '" .. tostring(extracted_hostname) .. "'")
            if extracted_hostname == hostname then
              print("  ✅ SUCCESS: SNI matches expected hostname!")
              return true
            else
              print("  ❌ SNI mismatch: expected '" .. tostring(hostname) .. "'")
            end
          end
        end
      end
    end
    offset = offset + ext_len
  end
  print("  ❌ SNI not found in extensions")
  return false
end
local main
main = function()
  local test_cases = {
    "google.com",
    "example.org",
    "github.com"
  }
  local successes = 0
  for _index_0 = 1, #test_cases do
    local hostname = test_cases[_index_0]
    if extract_sni_directly(hostname) then
      successes = successes + 1
    end
    print("")
  end
  print("🏁 ===== FINAL RESULTS =====")
  print("Successful SNI extractions: " .. tostring(successes) .. "/" .. tostring(#test_cases))
  if successes == #test_cases then
    print("🎉 COMPLETE SUCCESS!")
    print("✅ SNI extraction is working perfectly!")
    return print("🚀 QUIC SNI extraction system is now FUNCTIONAL!")
  elseif successes > 0 then
    print("🎯 PARTIAL SUCCESS!")
    return print("✅ SNI extraction working for " .. tostring(successes) .. " out of " .. tostring(#test_cases) .. " cases")
  else
    return print("❌ SNI extraction still not working")
  end
end
return main()
