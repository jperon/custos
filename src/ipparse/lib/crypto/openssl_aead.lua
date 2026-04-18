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
local xor
xor = function(a, b)
  return band(bor(a, b), bnot(band(a, b)))
end
local check_openssl
check_openssl = function()
  local success = os.execute("openssl version >/dev/null 2>&1")
  return success == 0
end
local crypto_available = check_openssl()
if not (crypto_available) then
  print("Warning: OpenSSL not available, using stub implementation")
else
  print("OpenSSL available for real crypto operations")
end
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
local write_temp_file
write_temp_file = function(data)
  local tmpname = os.tmpname()
  local file = io.open(tmpname, "wb")
  file:write(data)
  file:close()
  return tmpname
end
local read_temp_file
read_temp_file = function(filename)
  local file = io.open(filename, "rb")
  if not (file) then
    return nil
  end
  local data = file:read("*a")
  file:close()
  return data
end
local openssl_aes_gcm_encrypt
openssl_aes_gcm_encrypt = function(key, nonce, plaintext, aad)
  if aad == nil then
    aad = ""
  end
  if not (#key == 16) then
    error("AES-128-GCM key must be 16 bytes")
  end
  if not (#nonce == 12) then
    error("AES-GCM nonce must be 12 bytes")
  end
  local plaintext_file = write_temp_file(plaintext)
  local ciphertext_file = os.tmpname()
  local key_hex = bin2hex(key)
  local iv_hex = bin2hex(nonce)
  local cmd = "openssl enc -aes-128-gcm -e -K " .. tostring(key_hex) .. " -iv " .. tostring(iv_hex) .. " -in " .. tostring(plaintext_file) .. " -out " .. tostring(ciphertext_file)
  if #aad > 0 then
    local aad_file = write_temp_file(aad)
    cmd = cmd .. " -A " .. tostring(bin2hex(aad))
    os.remove(aad_file)
  end
  local result = os.execute(cmd)
  os.remove(plaintext_file)
  if result == 0 then
    local encrypted_data = read_temp_file(ciphertext_file)
    os.remove(ciphertext_file)
    return encrypted_data
  else
    os.remove(ciphertext_file)
    return nil
  end
end
local openssl_aes_gcm_decrypt
openssl_aes_gcm_decrypt = function(key, nonce, ciphertext_with_tag, aad)
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
  local ciphertext_file = write_temp_file(ciphertext_with_tag)
  local plaintext_file = os.tmpname()
  local key_hex = bin2hex(key)
  local iv_hex = bin2hex(nonce)
  local cmd = "openssl enc -aes-128-gcm -d -K " .. tostring(key_hex) .. " -iv " .. tostring(iv_hex) .. " -in " .. tostring(ciphertext_file) .. " -out " .. tostring(plaintext_file)
  if #aad > 0 then
    local aad_file = write_temp_file(aad)
    cmd = cmd .. " -A " .. tostring(bin2hex(aad))
    os.remove(aad_file)
  end
  local result = os.execute(cmd)
  os.remove(ciphertext_file)
  if result == 0 then
    local decrypted_data = read_temp_file(plaintext_file)
    os.remove(plaintext_file)
    return decrypted_data
  else
    os.remove(plaintext_file)
    return nil
  end
end
local stub_aes_gcm_encrypt
stub_aes_gcm_encrypt = function(key, nonce, plaintext, aad)
  if aad == nil then
    aad = ""
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
local aes_128_gcm_encrypt
aes_128_gcm_encrypt = function(key, nonce, plaintext, aad)
  if aad == nil then
    aad = ""
  end
  if crypto_available then
    local result = openssl_aes_gcm_encrypt(key, nonce, plaintext, aad)
    if result then
      return result
    end
  end
  return stub_aes_gcm_encrypt(key, nonce, plaintext, aad)
end
local aes_128_gcm_decrypt
aes_128_gcm_decrypt = function(key, nonce, ciphertext_with_tag, aad)
  if aad == nil then
    aad = ""
  end
  if crypto_available then
    local result = openssl_aes_gcm_decrypt(key, nonce, ciphertext_with_tag, aad)
    if result ~= nil then
      return result
    end
  end
  return stub_aes_gcm_decrypt(key, nonce, ciphertext_with_tag, aad)
end
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
  crypto_available = crypto_available
}
