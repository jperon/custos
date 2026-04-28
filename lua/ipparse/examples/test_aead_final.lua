local aead = require("ipparse.lib.crypto.aead")
local bin2hex, hex2bin
do
  local _obj_0 = require("ipparse.init")
  bin2hex, hex2bin = _obj_0.bin2hex, _obj_0.hex2bin
end
print("=== Final AEAD Test ===")
local key = string.rep("\x01", 16)
local nonce = string.rep("\x02", 12)
local plaintext = "Hello QUIC!"
print("Testing basic AES-GCM...")
print("Key length: " .. tostring(#key))
print("Nonce length: " .. tostring(#nonce))
print("Plaintext: " .. tostring(plaintext))
local encrypted = aead.aes_128_gcm_encrypt(key, nonce, plaintext, "")
if encrypted then
  print("✓ Encryption successful, length: " .. tostring(#encrypted))
  local decrypted = aead.aes_128_gcm_decrypt(key, nonce, encrypted, "")
  if decrypted == plaintext then
    print("✓ Decryption successful: " .. tostring(decrypted))
    print("✓ Round-trip test PASSED")
  else
    print("✗ Decryption mismatch: got '" .. tostring(decrypted) .. "', expected '" .. tostring(plaintext) .. "'")
  end
else
  print("✗ Encryption failed")
end
print("\nTesting QUIC packet protection...")
local packet_key = string.rep("\xAA", 16)
local packet_iv = string.rep("\xBB", 12)
local packet_number = 42
local payload = "QUIC frame data"
local header = "QUIC header"
local encrypted_packet = aead.quic_encrypt_packet(packet_key, packet_iv, packet_number, payload, header)
if encrypted_packet then
  print("✓ QUIC packet encryption successful")
  local decrypted_packet = aead.quic_decrypt_packet(packet_key, packet_iv, packet_number, encrypted_packet, header)
  if decrypted_packet == payload then
    print("✓ QUIC packet decryption successful")
    print("✓ QUIC packet protection test PASSED")
  else
    print("✗ QUIC packet decryption failed")
  end
else
  print("✗ QUIC packet encryption failed")
end
return print("\nPhase 3 (AEAD) implementation complete!")
