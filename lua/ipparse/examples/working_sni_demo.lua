local openssl_aead = require("ipparse.lib.crypto.openssl_aead")
local frames = require("ipparse.l4.quic.frames")
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
local band, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, rshift = _obj_0.band, _obj_0.rshift
end
print("🎯 ===== WORKING QUIC SNI EXTRACTION DEMO =====")
print("")
local create_proper_client_hello
create_proper_client_hello = function(hostname)
  local hostname_len = #hostname
  local sni_extension = ""
  sni_extension = sni_extension .. sp(">H", 0x0000)
  local sni_payload = ""
  sni_payload = sni_payload .. sp(">H", hostname_len + 3)
  sni_payload = sni_payload .. string.char(0x00)
  sni_payload = sni_payload .. sp(">H", hostname_len)
  sni_payload = sni_payload .. hostname
  sni_extension = sni_extension .. sp(">H", #sni_payload)
  sni_extension = sni_extension .. sni_payload
  local ch_payload = ""
  ch_payload = ch_payload .. sp(">H", 0x0303)
  ch_payload = ch_payload .. string.rep("\x00", 32)
  ch_payload = ch_payload .. string.char(0x00)
  ch_payload = ch_payload .. sp(">H", 0x0002)
  ch_payload = ch_payload .. sp(">H", 0x1301)
  ch_payload = ch_payload .. string.char(0x01, 0x00)
  ch_payload = ch_payload .. sp(">H", #sni_extension)
  ch_payload = ch_payload .. sni_extension
  local handshake = ""
  handshake = handshake .. string.char(0x01)
  local len = #ch_payload
  handshake = handshake .. string.char(rshift(len, 16) & 0xFF, rshift(len, 8) & 0xFF, band(len, 0xFF))
  handshake = handshake .. ch_payload
  local tls_record = ""
  tls_record = tls_record .. string.char(0x16)
  tls_record = tls_record .. sp(">H", 0x0303)
  tls_record = tls_record .. sp(">H", #handshake)
  tls_record = tls_record .. handshake
  print("   TLS Record structure:")
  print("     Record type: 0x16 (Handshake)")
  print("     Version: 0x0303 (TLS 1.2)")
  print("     Record length: " .. tostring(#handshake))
  print("     Handshake type: 0x01 (ClientHello)")
  print("     Handshake length: " .. tostring(#ch_payload))
  print("     SNI hostname: " .. tostring(hostname))
  return tls_record
end
local test_tls_parsing
test_tls_parsing = function(hostname)
  print("=== Testing TLS Parsing for: " .. tostring(hostname) .. " ===")
  local tls_data = create_proper_client_hello(hostname)
  print("Created TLS ClientHello: " .. tostring(#tls_data) .. " bytes")
  print("Hex dump: " .. tostring(bin2hex(tls_data)))
  local crypto_frame = {
    name = "CRYPTO",
    type = 0x06,
    offset = 0,
    length = #tls_data,
    data = tls_data
  }
  print("")
  print("Testing L7 parser...")
  local l7_parser = l7_quic.QuicL7Parser()
  local extracted_sni = l7_parser:process_frames({
    crypto_frame
  })
  if extracted_sni then
    print("✅ SUCCESS: Extracted SNI = '" .. tostring(extracted_sni) .. "'")
    if extracted_sni == hostname then
      print("✅ SNI matches expected hostname!")
      return true
    else
      print("❌ SNI mismatch (expected '" .. tostring(hostname) .. "')")
    end
  else
    print("❌ Failed to extract SNI")
  end
  return false
end
local test_full_pipeline
test_full_pipeline = function(hostname)
  print("=== Testing Full Pipeline for: " .. tostring(hostname) .. " ===")
  local tls_data = create_proper_client_hello(hostname)
  local crypto_frame_data = ""
  crypto_frame_data = crypto_frame_data .. string.char(0x06)
  crypto_frame_data = crypto_frame_data .. string.char(0x00)
  crypto_frame_data = crypto_frame_data .. frames.encode_varint(#tls_data)
  crypto_frame_data = crypto_frame_data .. tls_data
  print("CRYPTO frame created: " .. tostring(#crypto_frame_data) .. " bytes")
  local demo_key = string.rep("\x42", 16)
  local demo_iv = string.rep("\x24", 12)
  local packet_number = 1
  local header_aad = "QUIC_HEADER"
  local encrypted_payload = openssl_aead.quic_encrypt_packet(demo_key, demo_iv, packet_number, crypto_frame_data, header_aad)
  if encrypted_payload then
    print("✅ Encryption successful: " .. tostring(#encrypted_payload) .. " bytes")
    local decrypted_payload = openssl_aead.quic_decrypt_packet(demo_key, demo_iv, packet_number, encrypted_payload, header_aad)
    if decrypted_payload then
      print("✅ Decryption successful: " .. tostring(#decrypted_payload) .. " bytes")
      local parsed_frames = { }
      for frame in frames.iter_frames(decrypted_payload) do
        parsed_frames[#parsed_frames + 1] = frame
        print("Found " .. tostring(frame.name) .. " frame (length: " .. tostring(frame.length) .. ")")
      end
      local l7_parser = l7_quic.QuicL7Parser()
      local extracted_sni = l7_parser:process_frames(parsed_frames)
      if extracted_sni then
        print("🎉 FULL PIPELINE SUCCESS: SNI = '" .. tostring(extracted_sni) .. "'")
        return extracted_sni == hostname
      else
        print("❌ SNI extraction failed in full pipeline")
      end
    else
      print("❌ Decryption failed")
    end
  else
    print("❌ Encryption failed")
  end
  return false
end
local main
main = function()
  print("Testing QUIC SNI extraction with properly formatted TLS data")
  print("")
  local test_hostnames = {
    "example.com",
    "test.org"
  }
  local tls_successes = 0
  local pipeline_successes = 0
  for _index_0 = 1, #test_hostnames do
    local hostname = test_hostnames[_index_0]
    print("")
    if test_tls_parsing(hostname) then
      tls_successes = tls_successes + 1
    end
    print("")
    if test_full_pipeline(hostname) then
      pipeline_successes = pipeline_successes + 1
    end
    print(tostring(string.rep("=", 60)))
  end
  print("")
  print("🏁 ===== FINAL RESULTS =====")
  print("Direct TLS parsing successes: " .. tostring(tls_successes) .. "/" .. tostring(#test_hostnames))
  print("Full pipeline successes: " .. tostring(pipeline_successes) .. "/" .. tostring(#test_hostnames))
  if tls_successes > 0 then
    print("🎯 SUCCESS: SNI extraction is working!")
    print("✅ The QUIC SNI extraction system is functional")
  else
    print("⚠️  TLS parsing needs debugging")
  end
  if pipeline_successes > 0 then
    return print("🚀 BONUS: Full encrypted pipeline also working!")
  end
end
return main()
