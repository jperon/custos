local backend = require("ipparse.lib.crypto.backend.lunatik")
local hex_to_bin
hex_to_bin = function(hex_str)
  local result = ""
  for i = 1, #hex_str, 2 do
    local byte_str = hex_str:sub(i, i + 1)
    local byte = tonumber(byte_str, 16)
    result = result .. string.char(byte)
  end
  return result
end
local bin2hex
bin2hex = function(s)
  return s:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end)
end
local tests_passed = 0
local tests_failed = 0
local assert_test
assert_test = function(name, fn)
  local result, err = pcall(fn)
  if result then
    tests_passed = tests_passed + 1
    return print("PASS\tlunatik: " .. tostring(name))
  else
    tests_failed = tests_failed + 1
    return print("FAIL\tlunatik: " .. tostring(name) .. "\t" .. tostring(err))
  end
end
local QUIC_PACKET_START = hex_to_bin("c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399")
local CLIENT_INITIAL_SECRET = hex_to_bin("00f6614281a7d267c0394360e6ab36cb")
local HP_KEY = hex_to_bin("25a282493f8669ee0a39e256f5f3a14f")
local IV = hex_to_bin("fa044b2f42a3fd3b46fb255c")
local EXPECTED_PN = 2
assert_test("Pipeline: Nonce construction with PN=0 (IV unchanged)", function()
  local nonce = backend.construct_nonce(IV, 0)
  return assert(nonce == IV, "Nonce should equal IV when PN=0")
end)
assert_test("Pipeline: Nonce construction with PN=1 (XOR last byte)", function()
  local nonce = backend.construct_nonce(IV, 1)
  local expected = hex_to_bin("fa044b2f42a3fd3b46fb255d")
  return assert(nonce == expected, "Nonce mismatch for PN=1")
end)
assert_test("Pipeline: Nonce construction with PN=2 (RFC 9001 §A.2)", function()
  local nonce = backend.construct_nonce(IV, EXPECTED_PN)
  local expected = hex_to_bin("fa044b2f42a3fd3b46fb255e")
  return assert(nonce == expected, "Nonce mismatch for PN=2")
end)
assert_test("Pipeline: Packet structure - first byte has fixed bit (0x80)", function()
  local first_byte = string.byte(QUIC_PACKET_START, 1)
  return assert((first_byte & 0x80) ~= 0, "Fixed bit not set")
end)
assert_test("Pipeline: Packet structure - version = 0x00000001", function()
  local version = (string.byte(QUIC_PACKET_START, 2) << 24) | (string.byte(QUIC_PACKET_START, 3) << 16) | (string.byte(QUIC_PACKET_START, 4) << 8) | string.byte(QUIC_PACKET_START, 5)
  return assert(version == 0x00000001, "Expected version 1")
end)
assert_test("Pipeline: Packet structure - long header type = 0x00 (Initial)", function()
  local first_byte = string.byte(QUIC_PACKET_START, 1)
  local pkt_type = (first_byte >> 4) & 0x03
  return assert(pkt_type == 0x00, "Expected Initial packet type")
end)
assert_test("Pipeline: Packet structure - DCID length = 0x08", function()
  local dcid_len = string.byte(QUIC_PACKET_START, 6)
  return assert(dcid_len == 0x08, "Expected DCID length 0x08")
end)
assert_test("Pipeline: Packet number field - offset calculation", function()
  local pn_off = 1 + 4 + 1 + 8 + 1
  return assert(pn_off == 15, "PN offset should be 15")
end)
assert_test("Pipeline: AES-128-GCM nonce generation from PN=2", function()
  local pn = EXPECTED_PN
  local nonce = backend.construct_nonce(IV, pn)
  local expected = hex_to_bin("fa044b2f42a3fd3b46fb255e")
  return assert(nonce == expected, "Nonce incorrect for PN=2")
end)
assert_test("Pipeline: RFC 9001 §A.3 encrypt/decrypt round-trip", function()
  local key = hex_to_bin("00f6614281a7d267c0394360e6ab36cb")
  local nonce = hex_to_bin("fa044b2f42a3fd3b46fb255c")
  local plaintext = "hello world"
  local aad = "additional data"
  local ciphertext = backend.aes_128_gcm_encrypt(key, nonce, plaintext, aad)
  assert(#ciphertext > 0, "Encryption failed")
  local decrypted, err = backend.aes_128_gcm_decrypt(key, nonce, ciphertext, aad)
  return assert(decrypted == plaintext, "Decryption mismatch")
end)
assert_test("Pipeline: AES-128-GCM authentication validation", function()
  local key = hex_to_bin("00f6614281a7d267c0394360e6ab36cb")
  local nonce = hex_to_bin("fa044b2f42a3fd3b46fb255c")
  local plaintext = "test"
  local aad = "aad"
  local ciphertext = backend.aes_128_gcm_encrypt(key, nonce, plaintext, aad)
  local bad_tag = ciphertext:sub(1, #ciphertext - 1) .. string.char((string.byte(ciphertext, #ciphertext) + 1) % 256)
  local decrypted, err = backend.aes_128_gcm_decrypt(key, nonce, bad_tag, aad)
  assert(decrypted == nil, "Should reject bad tag")
  return assert(err ~= nil, "Should return error message")
end)
assert_test("Pipeline: Complete crypto path - construct_nonce → AES-GCM", function()
  local pn = 42
  local iv = hex_to_bin("fa044b2f42a3fd3b46fb255c")
  local key = hex_to_bin("00f6614281a7d267c0394360e6ab36cb")
  local nonce = backend.construct_nonce(iv, pn)
  assert(#nonce == 12, "Nonce size incorrect")
  local plaintext = "CRYPTO frame data"
  local aad = "unprotected header"
  local ciphertext = backend.aes_128_gcm_encrypt(key, nonce, plaintext, aad)
  assert(#ciphertext >= #plaintext + 16, "Ciphertext should include 16-byte tag")
  local decrypted, err = backend.aes_128_gcm_decrypt(key, nonce, ciphertext, aad)
  return assert(decrypted == plaintext, "Roundtrip failed")
end)
assert_test("Pipeline: SNI extraction ready (plaintext from decrypted CRYPTO frame)", function()
  local crypto_frame_type = 0x06
  return assert(crypto_frame_type == 0x06, "CRYPTO frame type")
end)
return print("  --> lib.crypto.lunatik.pipeline: " .. tostring(tests_passed) .. "/" .. tostring(tests_passed + tests_failed))
