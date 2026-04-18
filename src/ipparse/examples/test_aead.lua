local aead = require("ipparse.lib.crypto.aead")
local bin2hex, hex2bin
do
  local _obj_0 = require("ipparse.init")
  bin2hex, hex2bin = _obj_0.bin2hex, _obj_0.hex2bin
end
local band, bor, bnot, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, lshift, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.lshift, _obj_0.rshift
end
print("=== Testing AEAD Module ===")
print("Crypto available: " .. tostring(aead.crypto_available))
print("")
print("=== Nonce Construction Test ===")
local iv = hex2bin("000102030405060708090a0b")
local packet_number = 0x12345678
local nonce = aead.construct_nonce(iv, packet_number)
print("IV: " .. tostring(bin2hex(iv)))
print("Packet Number: 0x" .. tostring(string.format("%08x", packet_number)))
print("Constructed Nonce: " .. tostring(bin2hex(nonce)))
local expected_nonce = hex2bin("000102030405060000000000")
local expected_bytes = {
  0x00,
  0x01,
  0x02,
  0x03,
  0x04,
  0x05,
  0x06,
  0x78,
  0x56,
  0x34,
  0x12,
  0x0b
}
local expected_hex = ""
for _index_0 = 1, #expected_bytes do
  local b = expected_bytes[_index_0]
  expected_hex = expected_hex .. string.format("%02x", b)
end
print("Expected result (manual calculation):")
print("  First 4 bytes: 00010203")
print("  Packet number (8 bytes BE): 0000000012345678")
print("  IV last 8 bytes: 0405060708090a0b")
print("  XOR result: " .. tostring(string.format("%02x%02x%02x%02x%02x%02x%02x%02x", band(bor(0x04, 0x00), bnot(band(0x04, 0x00))), band(bor(0x05, 0x00), bnot(band(0x05, 0x00))), band(bor(0x06, 0x00), bnot(band(0x06, 0x00))), band(bor(0x07, 0x00), bnot(band(0x07, 0x00))), band(bor(0x08, 0x12), bnot(band(0x08, 0x12))), band(bor(0x09, 0x34), bnot(band(0x09, 0x34))), band(bor(0x0a, 0x56), bnot(band(0x0a, 0x56))), band(bor(0x0b, 0x78), bnot(band(0x0b, 0x78))))))
print("")
print("=== AES-128-GCM Test ===")
local key = hex2bin("000102030405060708090a0b0c0d0e0f")
local test_nonce = hex2bin("000102030405060708090a0b")
local plaintext = "Hello, QUIC World!"
local aad = "QUIC Header Data"
print("Key: " .. tostring(bin2hex(key)))
print("Nonce: " .. tostring(bin2hex(test_nonce)))
print("Plaintext: " .. tostring(plaintext))
print("AAD: " .. tostring(aad))
print("")
print("Encrypting...")
local ciphertext_with_tag = aead.aes_128_gcm_encrypt(key, test_nonce, plaintext, aad)
if ciphertext_with_tag then
  print("✓ Encryption successful")
  print("  Ciphertext+Tag length: " .. tostring(#ciphertext_with_tag) .. " bytes")
  print("  Ciphertext+Tag: " .. tostring(bin2hex(ciphertext_with_tag)))
  print("")
  print("Decrypting...")
  local decrypted = aead.aes_128_gcm_decrypt(key, test_nonce, ciphertext_with_tag, aad)
  if decrypted then
    print("✓ Decryption successful")
    print("  Decrypted: " .. tostring(decrypted))
    if decrypted == plaintext then
      print("✓ Round-trip successful - decrypted text matches original")
    else
      print("✗ Round-trip failed - decrypted text doesn't match")
    end
  else
    print("✗ Decryption failed")
  end
else
  print("✗ Encryption failed")
end
print("")
print("=== QUIC Packet Protection Test ===")
local packet_key = hex2bin("fedcba9876543210fedcba9876543210")
local packet_iv = hex2bin("abcdef0123456789abcdef01")
local packet_num = 0x42
local packet_payload = "QUIC frames data here"
local header_data = hex2bin("c0000001")
print("Packet Key: " .. tostring(bin2hex(packet_key)))
print("Packet IV: " .. tostring(bin2hex(packet_iv)))
print("Packet Number: " .. tostring(packet_num))
print("Payload: " .. tostring(packet_payload))
print("Header AAD: " .. tostring(bin2hex(header_data)))
print("")
print("Encrypting QUIC packet...")
local encrypted_payload = aead.quic_encrypt_packet(packet_key, packet_iv, packet_num, packet_payload, header_data)
if encrypted_payload then
  print("✓ Packet encryption successful")
  print("  Encrypted length: " .. tostring(#encrypted_payload) .. " bytes")
  print("  Encrypted: " .. tostring(bin2hex(encrypted_payload)))
  print("")
  print("Decrypting QUIC packet...")
  local decrypted_payload = aead.quic_decrypt_packet(packet_key, packet_iv, packet_num, encrypted_payload, header_data)
  if decrypted_payload then
    print("✓ Packet decryption successful")
    print("  Decrypted: " .. tostring(decrypted_payload))
    if decrypted_payload == packet_payload then
      print("✓ QUIC packet protection round-trip successful")
    else
      print("✗ QUIC packet protection round-trip failed")
    end
  else
    print("✗ Packet decryption failed")
  end
else
  print("✗ Packet encryption failed")
end
print("")
print("=== Authentication Failure Test ===")
print("Testing with wrong key...")
local wrong_key = hex2bin("ffffffffffffffffffffffffffffffff")
local bad_decrypt = aead.aes_128_gcm_decrypt(wrong_key, test_nonce, ciphertext_with_tag, aad)
if bad_decrypt then
  print("✗ Authentication should have failed but didn't")
else
  print("✓ Authentication correctly failed with wrong key")
end
print("")
return print("=== AEAD Tests Complete ===")
