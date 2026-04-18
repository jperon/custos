#!/usr/bin/env moon

--- Simple AEAD Test
-- Basic test for AEAD module functionality

aead = require "ipparse.lib.crypto.aead"
:bin2hex, :hex2bin = require "ipparse.init"

print "=== Simple AEAD Test ==="

-- Test basic functionality
key = hex2bin "000102030405060708090a0b0c0d0e0f"  -- 16 bytes
nonce = hex2bin "000102030405060708090a0b"         -- 12 bytes
plaintext = "test"

print "Testing AES-GCM encrypt/decrypt..."
print "Key: #{bin2hex key}"
print "Nonce: #{bin2hex nonce}"
print "Plaintext: #{plaintext}"

-- Test encryption
ciphertext = aead.aes_128_gcm_encrypt key, nonce, plaintext, ""
if ciphertext
  print "✓ Encryption successful, length: #{#ciphertext}"

  -- Test decryption
  decrypted = aead.aes_128_gcm_decrypt key, nonce, ciphertext, ""
  if decrypted == plaintext
    print "✓ Decryption successful: #{decrypted}"
  else
    print "✗ Decryption failed"
else
  print "✗ Encryption failed"

print "AEAD test complete!"
