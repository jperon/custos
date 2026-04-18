#!/usr/bin/env moon

--- Final AEAD Test
-- Test the fixed AEAD module

aead = require "ipparse.lib.crypto.aead"
:bin2hex, :hex2bin = require "ipparse.init"

print "=== Final AEAD Test ==="

-- Test basic encrypt/decrypt
key = string.rep("\x01", 16)    -- 16 bytes of 0x01
nonce = string.rep("\x02", 12)  -- 12 bytes of 0x02
plaintext = "Hello QUIC!"

print "Testing basic AES-GCM..."
print "Key length: #{#key}"
print "Nonce length: #{#nonce}"
print "Plaintext: #{plaintext}"

-- Encrypt
encrypted = aead.aes_128_gcm_encrypt key, nonce, plaintext, ""
if encrypted
  print "✓ Encryption successful, length: #{#encrypted}"

  -- Decrypt
  decrypted = aead.aes_128_gcm_decrypt key, nonce, encrypted, ""
  if decrypted == plaintext
    print "✓ Decryption successful: #{decrypted}"
    print "✓ Round-trip test PASSED"
  else
    print "✗ Decryption mismatch: got '#{decrypted}', expected '#{plaintext}'"

else
  print "✗ Encryption failed"

-- Test QUIC packet protection
print "\nTesting QUIC packet protection..."
packet_key = string.rep("\xAA", 16)
packet_iv = string.rep("\xBB", 12)
packet_number = 42
payload = "QUIC frame data"
header = "QUIC header"

encrypted_packet = aead.quic_encrypt_packet packet_key, packet_iv, packet_number, payload, header
if encrypted_packet
  print "✓ QUIC packet encryption successful"

  decrypted_packet = aead.quic_decrypt_packet packet_key, packet_iv, packet_number, encrypted_packet, header
  if decrypted_packet == payload
    print "✓ QUIC packet decryption successful"
    print "✓ QUIC packet protection test PASSED"
  else
    print "✗ QUIC packet decryption failed"
else
  print "✗ QUIC packet encryption failed"

print "\nPhase 3 (AEAD) implementation complete!"
