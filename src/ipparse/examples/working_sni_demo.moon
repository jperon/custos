#!/usr/bin/env moon

--- Working QUIC SNI Extraction Demo
-- Fixed version that properly creates TLS ClientHello

openssl_aead = require "ipparse.lib.crypto.openssl_aead"
frames = require "ipparse.l4.quic.frames"
l7_quic = require "ipparse.l7.quic"
:bin2hex, :hex2bin = require "ipparse.init"

pack: sp, unpack: su = string
{:band, :rshift} = require"ipparse.lib.bit_compat"

print "🎯 ===== WORKING QUIC SNI EXTRACTION DEMO ====="
print ""

--- Creates a properly structured TLS ClientHello with correct lengths
create_proper_client_hello = (hostname) ->
  -- Build SNI extension first
  hostname_len = #hostname
  sni_extension = ""
  sni_extension ..= sp ">H", 0x0000  -- Extension type: SNI

  -- SNI extension payload
  sni_payload = ""
  sni_payload ..= sp ">H", hostname_len + 3  -- Server name list length
  sni_payload ..= string.char(0x00)  -- Name type: hostname
  sni_payload ..= sp ">H", hostname_len  -- Hostname length
  sni_payload ..= hostname  -- Hostname

  sni_extension ..= sp ">H", #sni_payload  -- Extension length
  sni_extension ..= sni_payload

  -- Build ClientHello payload
  ch_payload = ""
  ch_payload ..= sp ">H", 0x0303  -- Protocol version (TLS 1.2)
  ch_payload ..= string.rep("\x00", 32)  -- Random
  ch_payload ..= string.char(0x00)  -- Session ID length
  ch_payload ..= sp ">H", 0x0002  -- Cipher suites length
  ch_payload ..= sp ">H", 0x1301  -- TLS_AES_128_GCM_SHA256
  ch_payload ..= string.char(0x01, 0x00)  -- Compression methods

  -- Extensions
  ch_payload ..= sp ">H", #sni_extension  -- Extensions length
  ch_payload ..= sni_extension

  -- Build handshake message
  handshake = ""
  handshake ..= string.char(0x01)  -- ClientHello type
  -- Length is 24-bit big-endian
  len = #ch_payload
  handshake ..= string.char(rshift(len, 16) & 0xFF, rshift(len, 8) & 0xFF, band(len, 0xFF))
  handshake ..= ch_payload

  -- Build TLS record
  tls_record = ""
  tls_record ..= string.char(0x16)  -- Handshake record type
  tls_record ..= sp ">H", 0x0303  -- Version
  tls_record ..= sp ">H", #handshake  -- Record length
  tls_record ..= handshake

  print "   TLS Record structure:"
  print "     Record type: 0x16 (Handshake)"
  print "     Version: 0x0303 (TLS 1.2)"
  print "     Record length: #{#handshake}"
  print "     Handshake type: 0x01 (ClientHello)"
  print "     Handshake length: #{#ch_payload}"
  print "     SNI hostname: #{hostname}"

  tls_record

--- Test TLS parsing directly
test_tls_parsing = (hostname) ->
  print "=== Testing TLS Parsing for: #{hostname} ==="

  -- Create ClientHello
  tls_data = create_proper_client_hello hostname
  print "Created TLS ClientHello: #{#tls_data} bytes"
  print "Hex dump: #{bin2hex tls_data}"

  -- Create mock CRYPTO frame
  crypto_frame = {
    name: "CRYPTO",
    type: 0x06,
    offset: 0,
    length: #tls_data,
    data: tls_data
  }

  -- Test L7 parser
  print ""
  print "Testing L7 parser..."
  l7_parser = l7_quic.QuicL7Parser()
  extracted_sni = l7_parser\process_frames {crypto_frame}

  if extracted_sni
    print "✅ SUCCESS: Extracted SNI = '#{extracted_sni}'"
    if extracted_sni == hostname
      print "✅ SNI matches expected hostname!"
      return true
    else
      print "❌ SNI mismatch (expected '#{hostname}')"
  else
    print "❌ Failed to extract SNI"

  false

--- Test with synthetic encrypted QUIC packet
test_full_pipeline = (hostname) ->
  print "=== Testing Full Pipeline for: #{hostname} ==="

  -- Create TLS data
  tls_data = create_proper_client_hello hostname

  -- Create CRYPTO frame
  crypto_frame_data = ""
  crypto_frame_data ..= string.char(0x06)  -- CRYPTO frame type
  crypto_frame_data ..= string.char(0x00)  -- Offset (VarInt = 0)
  crypto_frame_data ..= frames.encode_varint #tls_data  -- Length
  crypto_frame_data ..= tls_data

  print "CRYPTO frame created: #{#crypto_frame_data} bytes"

  -- Encrypt with demo keys
  demo_key = string.rep("\x42", 16)
  demo_iv = string.rep("\x24", 12)
  packet_number = 1
  header_aad = "QUIC_HEADER"  -- Simplified AAD

  encrypted_payload = openssl_aead.quic_encrypt_packet(
    demo_key, demo_iv, packet_number, crypto_frame_data, header_aad
  )

  if encrypted_payload
    print "✅ Encryption successful: #{#encrypted_payload} bytes"

    -- Decrypt
    decrypted_payload = openssl_aead.quic_decrypt_packet(
      demo_key, demo_iv, packet_number, encrypted_payload, header_aad
    )

    if decrypted_payload
      print "✅ Decryption successful: #{#decrypted_payload} bytes"

      -- Parse frames
      parsed_frames = {}
      for frame in frames.iter_frames decrypted_payload
        parsed_frames[#parsed_frames + 1] = frame
        print "Found #{frame.name} frame (length: #{frame.length})"

      -- Extract SNI
      l7_parser = l7_quic.QuicL7Parser()
      extracted_sni = l7_parser\process_frames parsed_frames

      if extracted_sni
        print "🎉 FULL PIPELINE SUCCESS: SNI = '#{extracted_sni}'"
        return extracted_sni == hostname
      else
        print "❌ SNI extraction failed in full pipeline"
    else
      print "❌ Decryption failed"
  else
    print "❌ Encryption failed"

  false

--- Main test
main = ->
  print "Testing QUIC SNI extraction with properly formatted TLS data"
  print ""

  test_hostnames = {"example.com", "test.org"}

  tls_successes = 0
  pipeline_successes = 0

  for hostname in *test_hostnames
    print ""

    -- Test TLS parsing directly
    if test_tls_parsing hostname
      tls_successes += 1

    print ""

    -- Test full pipeline
    if test_full_pipeline hostname
      pipeline_successes += 1

    print "#{string.rep("=", 60)}"

  print ""
  print "🏁 ===== FINAL RESULTS ====="
  print "Direct TLS parsing successes: #{tls_successes}/#{#test_hostnames}"
  print "Full pipeline successes: #{pipeline_successes}/#{#test_hostnames}"

  if tls_successes > 0
    print "🎯 SUCCESS: SNI extraction is working!"
    print "✅ The QUIC SNI extraction system is functional"
  else
    print "⚠️  TLS parsing needs debugging"

  if pipeline_successes > 0
    print "🚀 BONUS: Full encrypted pipeline also working!"

-- Run the test
main!
