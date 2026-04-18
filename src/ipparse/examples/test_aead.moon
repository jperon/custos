#!/usr/bin/env moon

--- Test AEAD Encryption/Decryption
-- Tests the AEAD module for QUIC packet protection

aead = require "ipparse.lib.crypto.aead"
:bin2hex, :hex2bin = require "ipparse.init"
{:band, :bor, :bnot, :lshift, :rshift} = require "ipparse.lib.bit_compat"

print "=== Testing AEAD Module ==="
print "Crypto available: #{aead.crypto_available}"
print ""

-- Test nonce construction
print "=== Nonce Construction Test ==="
iv = hex2bin "000102030405060708090a0b"  -- 12 bytes
packet_number = 0x12345678

nonce = aead.construct_nonce iv, packet_number
print "IV: #{bin2hex iv}"
print "Packet Number: 0x#{string.format "%08x", packet_number}"
print "Constructed Nonce: #{bin2hex nonce}"

-- Expected: IV XOR with packet number in last 8 bytes
expected_nonce = hex2bin "000102030405060000000000"  -- First 4 bytes unchanged
-- XOR last 8 bytes with packet number (0x0000000012345678)
expected_bytes = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x78, 0x56, 0x34, 0x12, 0x0b}
expected_hex = ""
for b in *expected_bytes
  expected_hex ..= string.format "%02x", b

print "Expected result (manual calculation):"
print "  First 4 bytes: 00010203"
print "  Packet number (8 bytes BE): 0000000012345678"
print "  IV last 8 bytes: 0405060708090a0b"
print "  XOR result: #{string.format "%02x%02x%02x%02x%02x%02x%02x%02x", band(bor(0x04, 0x00), bnot(band(0x04, 0x00))), band(bor(0x05, 0x00), bnot(band(0x05, 0x00))), band(bor(0x06, 0x00), bnot(band(0x06, 0x00))), band(bor(0x07, 0x00), bnot(band(0x07, 0x00))), band(bor(0x08, 0x12), bnot(band(0x08, 0x12))), band(bor(0x09, 0x34), bnot(band(0x09, 0x34))), band(bor(0x0a, 0x56), bnot(band(0x0a, 0x56))), band(bor(0x0b, 0x78), bnot(band(0x0b, 0x78)))}"

print ""

-- Test AES-GCM encryption/decryption
print "=== AES-128-GCM Test ==="
key = hex2bin "000102030405060708090a0b0c0d0e0f"  -- 16 bytes
test_nonce = hex2bin "000102030405060708090a0b"       -- 12 bytes
plaintext = "Hello, QUIC World!"
aad = "QUIC Header Data"

print "Key: #{bin2hex key}"
print "Nonce: #{bin2hex test_nonce}"
print "Plaintext: #{plaintext}"
print "AAD: #{aad}"
print ""

-- Encrypt
print "Encrypting..."
ciphertext_with_tag = aead.aes_128_gcm_encrypt key, test_nonce, plaintext, aad

if ciphertext_with_tag
  print "✓ Encryption successful"
  print "  Ciphertext+Tag length: #{#ciphertext_with_tag} bytes"
  print "  Ciphertext+Tag: #{bin2hex ciphertext_with_tag}"

  -- Decrypt
  print ""
  print "Decrypting..."
  decrypted = aead.aes_128_gcm_decrypt key, test_nonce, ciphertext_with_tag, aad

  if decrypted
    print "✓ Decryption successful"
    print "  Decrypted: #{decrypted}"

    if decrypted == plaintext
      print "✓ Round-trip successful - decrypted text matches original"
    else
      print "✗ Round-trip failed - decrypted text doesn't match"
  else
    print "✗ Decryption failed"
else
  print "✗ Encryption failed"

print ""

-- Test QUIC packet protection
print "=== QUIC Packet Protection Test ==="
packet_key = hex2bin "fedcba9876543210fedcba9876543210"  -- 16 bytes
packet_iv = hex2bin "abcdef0123456789abcdef01"          -- 12 bytes
packet_num = 0x42
packet_payload = "QUIC frames data here"
header_data = hex2bin "c0000001"  -- Mock QUIC header

print "Packet Key: #{bin2hex packet_key}"
print "Packet IV: #{bin2hex packet_iv}"
print "Packet Number: #{packet_num}"
print "Payload: #{packet_payload}"
print "Header AAD: #{bin2hex header_data}"
print ""

-- Encrypt packet
print "Encrypting QUIC packet..."
encrypted_payload = aead.quic_encrypt_packet packet_key, packet_iv, packet_num, packet_payload, header_data

if encrypted_payload
  print "✓ Packet encryption successful"
  print "  Encrypted length: #{#encrypted_payload} bytes"
  print "  Encrypted: #{bin2hex encrypted_payload}"

  -- Decrypt packet
  print ""
  print "Decrypting QUIC packet..."
  decrypted_payload = aead.quic_decrypt_packet packet_key, packet_iv, packet_num, encrypted_payload, header_data

  if decrypted_payload
    print "✓ Packet decryption successful"
    print "  Decrypted: #{decrypted_payload}"

    if decrypted_payload == packet_payload
      print "✓ QUIC packet protection round-trip successful"
    else
      print "✗ QUIC packet protection round-trip failed"
  else
    print "✗ Packet decryption failed"
else
  print "✗ Packet encryption failed"

print ""

-- Test authentication failure
print "=== Authentication Failure Test ==="
print "Testing with wrong key..."
wrong_key = hex2bin "ffffffffffffffffffffffffffffffff"  -- Different key
bad_decrypt = aead.aes_128_gcm_decrypt wrong_key, test_nonce, ciphertext_with_tag, aad

if bad_decrypt
  print "✗ Authentication should have failed but didn't"
else
  print "✓ Authentication correctly failed with wrong key"

print ""
print "=== AEAD Tests Complete ==="
