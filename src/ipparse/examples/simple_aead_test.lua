local aead = require("ipparse.lib.crypto.aead")
local bin2hex, hex2bin
do
  local _obj_0 = require("ipparse.init")
  bin2hex, hex2bin = _obj_0.bin2hex, _obj_0.hex2bin
end
print("=== Simple AEAD Test ===")
local key = hex2bin("000102030405060708090a0b0c0d0e0f")
local nonce = hex2bin("000102030405060708090a0b")
local plaintext = "test"
print("Testing AES-GCM encrypt/decrypt...")
print("Key: " .. tostring(bin2hex(key)))
print("Nonce: " .. tostring(bin2hex(nonce)))
print("Plaintext: " .. tostring(plaintext))
local ciphertext = aead.aes_128_gcm_encrypt(key, nonce, plaintext, "")
if ciphertext then
  print("✓ Encryption successful, length: " .. tostring(#ciphertext))
  local decrypted = aead.aes_128_gcm_decrypt(key, nonce, ciphertext, "")
  if decrypted == plaintext then
    print("✓ Decryption successful: " .. tostring(decrypted))
  else
    print("✗ Decryption failed")
  end
else
  print("✗ Encryption failed")
end
return print("AEAD test complete!")
