#!/usr/bin/env moon

--- Test QUIC L7 SNI Extraction
-- Test the actual L7 parser with our working SNI data

l7_quic = require "ipparse.l7.quic"
:bin2hex, :hex2bin = require "ipparse.init"
pack: sp, unpack: su = string
{:band, :rshift} = require"ipparse.lib.bit_compat"

print "🧪 Testing QUIC L7 SNI Extraction"
print ""

-- Create a ClientHello message with SNI
create_client_hello_with_sni = (hostname) ->
  -- SNI extension data
  sni_name_list = sp(">H", #hostname + 3) .. string.char(0x00) .. sp(">H", #hostname) .. hostname
  sni_extension = sp(">H", 0x0000) .. sp(">H", #sni_name_list) .. sni_name_list

  -- Extensions wrapper
  extensions_data = sp(">H", #sni_extension) .. sni_extension

  -- ClientHello payload
  client_hello = ""
  client_hello ..= sp ">H", 0x0303  -- TLS version
  client_hello ..= string.rep("\x00", 32)  -- Random (32 bytes)
  client_hello ..= string.char(0x00)  -- Session ID length
  client_hello ..= sp(">H", 2) .. sp(">H", 0x1301)  -- Cipher suites (2 bytes length, 1 suite)
  client_hello ..= string.char(0x01, 0x00)  -- Compression methods (1 byte length, null compression)
  client_hello ..= extensions_data

  -- Handshake message
  handshake_length = #client_hello
  handshake_msg = string.char(0x01)  -- ClientHello type
  handshake_msg ..= string.char(0x00, rshift(handshake_length, 8) & 0xFF, band(handshake_length, 0xFF))  -- 24-bit length
  handshake_msg ..= client_hello

  handshake_msg

-- Test the L7 parser
test_l7_parser = (hostname) ->
  print "=== Testing L7 parser with: #{hostname} ==="

  client_hello_data = create_client_hello_with_sni hostname

  -- Create a mock handshake message
  client_hello_msg = {
    type: 1,
    name: "ClientHello",
    data: client_hello_data\sub(5),  -- Skip the handshake header
    length: #client_hello_data - 4
  }

  print "Created ClientHello message:"
  print "  Type: #{client_hello_msg.type}"
  print "  Name: #{client_hello_msg.name}"
  print "  Data length: #{client_hello_msg.length}"
  print ""

  -- Test the extract_sni_from_client_hello method
  parser = l7_quic.QuicL7Parser()
  sni = parser\extract_sni_from_client_hello client_hello_msg

  if sni
    print "  ✅ SUCCESS: Extracted SNI '#{sni}'"
    if sni == hostname
      print "  ✅ SNI matches expected hostname!"
      return true
    else
      print "  ❌ SNI mismatch: expected '#{hostname}'"
  else
    print "  ❌ FAILED: No SNI extracted"

  print ""
  false

-- Test multiple hostnames
test_cases = {"google.com", "example.org", "github.com"}
successes = 0

for hostname in *test_cases
  if test_l7_parser hostname
    successes += 1

print "🏁 Results: #{successes}/#{#test_cases} successful"

if successes == #test_cases
  print "🎉 SUCCESS: QUIC L7 SNI extraction is working!"
else
  print "❌ FAILURE: QUIC L7 SNI extraction needs more debugging"
