local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
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
local real_aead
local crypto_available = false
local success, aead_module = pcall(require, "ipparse.lib.crypto.aead")
if success then
  real_aead = aead_module
  crypto_available = true
else
  local lua_aead
  success, lua_aead = pcall(dofile, "lib/crypto/aead.lua")
  if success then
    real_aead = lua_aead
    crypto_available = true
  else
    local parent_aead
    success, parent_aead = pcall(dofile, "../lib/crypto/aead.lua")
    if success then
      real_aead = parent_aead
      crypto_available = true
    end
  end
end
if not (crypto_available) then
  print("Warning: Real crypto not available, falling back to stub implementation")
end
local xor
xor = function(a, b)
  return band(bor(a, b), bnot(band(a, b)))
end
local aead_algorithms = {
  AES_128_GCM = "AES-128-GCM",
  AES_256_GCM = "AES-256-GCM",
  CHACHA20_POLY1305 = "ChaCha20-Poly1305"
}
local construct_nonce
construct_nonce = function(iv, packet_number)
  if #iv ~= 12 then
    error("IV must be 12 bytes for QUIC AEAD")
  end
  local pn_bytes = sp(">I8", packet_number)
  local nonce = iv:sub(1, 4)
  for i = 1, 8 do
    local iv_byte = su("B", iv, 4 + i)
    local pn_byte = su("B", pn_bytes, i)
    nonce = nonce .. sp("B", xor(iv_byte, pn_byte))
  end
  return nonce
end
local real_aes_128_gcm_encrypt
real_aes_128_gcm_encrypt = function(key, nonce, plaintext, aad)
  if aad == nil then
    aad = ""
  end
  if not (#key == 16) then
    error("AES-128-GCM key must be 16 bytes")
  end
  if not (#nonce == 12) then
    error("AES-GCM nonce must be 12 bytes")
  end
  if crypto_available and real_aead then
    local cipher = real_aead.new("gcm(aes)")
    cipher:setkey(key)
    cipher:setauthsize(16)
    local result = cipher:encrypt(nonce, plaintext, aad)
    return result
  else
    return stub_aes_gcm_encrypt(key, nonce, plaintext, aad)
  end
end
local real_aes_128_gcm_decrypt
real_aes_128_gcm_decrypt = function(key, nonce, ciphertext_with_tag, aad)
  if aad == nil then
    aad = ""
  end
  if not (#key == 16) then
    error("AES-128-GCM key must be 16 bytes")
  end
  if not (#nonce == 12) then
    error("AES-GCM nonce must be 12 bytes")
  end
  if not (#ciphertext_with_tag >= 16) then
    return nil
  end
  if crypto_available and real_aead then
    local cipher = real_aead.new("gcm(aes)")
    cipher:setkey(key)
    cipher:setauthsize(16)
    local result, err = cipher:decrypt(nonce, ciphertext_with_tag, aad)
    return result
  else
    return stub_aes_gcm_decrypt(key, nonce, ciphertext_with_tag, aad)
  end
end
local stub_aes_gcm_encrypt
stub_aes_gcm_encrypt = function(key, nonce, plaintext, aad)
  if aad == nil then
    aad = ""
  end
  if not (#key == 16) then
    error("AES-128-GCM key must be 16 bytes")
  end
  if not (#nonce == 12) then
    error("AES-GCM nonce must be 12 bytes")
  end
  local ciphertext = ""
  for i = 1, #plaintext do
    local p = string.byte(plaintext, i)
    local k = string.byte(key, ((i - 1) % #key) + 1)
    ciphertext = ciphertext .. string.char(xor(p, k))
  end
  local auth_tag = ""
  for i = 1, 16 do
    local k = string.byte(key, ((i - 1) % #key) + 1)
    local n = string.byte(nonce, ((i - 1) % #nonce) + 1)
    auth_tag = auth_tag .. string.char(xor(k, n))
  end
  return ciphertext .. auth_tag
end
local stub_aes_gcm_decrypt
stub_aes_gcm_decrypt = function(key, nonce, ciphertext_with_tag, aad)
  if aad == nil then
    aad = ""
  end
  if not (#key == 16) then
    error("AES-128-GCM key must be 16 bytes")
  end
  if not (#nonce == 12) then
    error("AES-GCM nonce must be 12 bytes")
  end
  if not (#ciphertext_with_tag >= 16) then
    return nil
  end
  local ciphertext = ciphertext_with_tag:sub(1, #ciphertext_with_tag - 16)
  local received_tag = ciphertext_with_tag:sub(#ciphertext_with_tag - 15)
  local expected_tag = ""
  for i = 1, 16 do
    local k = string.byte(key, ((i - 1) % #key) + 1)
    local n = string.byte(nonce, ((i - 1) % #nonce) + 1)
    expected_tag = expected_tag .. string.char(xor(k, n))
  end
  if received_tag ~= expected_tag then
    return nil
  end
  local plaintext = ""
  for i = 1, #ciphertext do
    local c = string.byte(ciphertext, i)
    local k = string.byte(key, ((i - 1) % #key) + 1)
    plaintext = plaintext .. string.char(xor(c, k))
  end
  return plaintext
end
local aes_128_gcm_encrypt = real_aes_gcm_encrypt
local aes_128_gcm_decrypt = real_aes_128_gcm_decrypt
local aead_encrypt
aead_encrypt = function(algorithm, key, nonce, plaintext, aad)
  if aad == nil then
    aad = ""
  end
  local _exp_0 = algorithm
  if "AES-128-GCM" == _exp_0 then
    return aes_128_gcm_encrypt(key, nonce, plaintext, aad)
  else
    return error("Unsupported AEAD algorithm: " .. tostring(algorithm))
  end
end
local aead_decrypt
aead_decrypt = function(algorithm, key, nonce, ciphertext_with_tag, aad)
  if aad == nil then
    aad = ""
  end
  local _exp_0 = algorithm
  if "AES-128-GCM" == _exp_0 then
    return aes_128_gcm_decrypt(key, nonce, ciphertext_with_tag, aad)
  else
    return error("Unsupported AEAD algorithm: " .. tostring(algorithm))
  end
end
local quic_encrypt_packet
quic_encrypt_packet = function(key, iv, packet_number, plaintext, header_aad)
  local nonce = construct_nonce(iv, packet_number)
  return aes_128_gcm_encrypt(key, nonce, plaintext, header_aad)
end
local quic_decrypt_packet
quic_decrypt_packet = function(key, iv, packet_number, ciphertext_with_tag, header_aad)
  local nonce = construct_nonce(iv, packet_number)
  return aes_128_gcm_decrypt(key, nonce, ciphertext_with_tag, header_aad)
end
return {
  aead_encrypt = aead_encrypt,
  aead_decrypt = aead_decrypt,
  aes_128_gcm_encrypt = aes_128_gcm_encrypt,
  aes_128_gcm_decrypt = aes_128_gcm_decrypt,
  construct_nonce = construct_nonce,
  quic_encrypt_packet = quic_encrypt_packet,
  quic_decrypt_packet = quic_decrypt_packet,
  aead_algorithms = aead_algorithms,
  crypto_available = crypto_available
}
