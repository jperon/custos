local aead, skcipher
do
  local _obj_0 = require("crypto")
  aead, skcipher = _obj_0.aead, _obj_0.skcipher
end
local validate_gcm_key, validate_gcm_nonce, validate_ecb_key, validate_ecb_block, validate_quic_iv
do
  local _obj_0 = require("ipparse.lib.crypto.backend.common")
  validate_gcm_key, validate_gcm_nonce, validate_ecb_key, validate_ecb_block, validate_quic_iv = _obj_0.validate_gcm_key, _obj_0.validate_gcm_nonce, _obj_0.validate_ecb_key, _obj_0.validate_ecb_block, _obj_0.validate_quic_iv
end
local close_tfm
close_tfm = function(tfm)
  if not (tfm and tfm.__close) then
    return 
  end
  return pcall(tfm.__close, tfm)
end
local cached_gcm_enc_tfm = nil
local cached_gcm_enc_key = nil
local cached_gcm_dec_tfm = nil
local cached_gcm_dec_key = nil
local cached_ecb_tfm = nil
local cached_ecb_key = nil
local ecb_fail_streak = 0
local get_gcm_tfm
get_gcm_tfm = function(mode, key)
  if mode == "encrypt" then
    if not (cached_gcm_enc_tfm) then
      cached_gcm_enc_tfm = aead("gcm(aes)")
      cached_gcm_enc_tfm:setauthsize(16)
    end
    if cached_gcm_enc_key ~= key then
      cached_gcm_enc_tfm:setkey(key)
      cached_gcm_enc_key = key
    end
    return cached_gcm_enc_tfm
  else
    if not (cached_gcm_dec_tfm) then
      cached_gcm_dec_tfm = aead("gcm(aes)")
      cached_gcm_dec_tfm:setauthsize(16)
    end
    if cached_gcm_dec_key ~= key then
      cached_gcm_dec_tfm:setkey(key)
      cached_gcm_dec_key = key
    end
    return cached_gcm_dec_tfm
  end
end
local xor8
xor8 = function(a, b)
  local res = 0
  local bit = 1
  for _ = 1, 8 do
    local abit = a % 2
    local bbit = b % 2
    if abit ~= bbit then
      res = res + bit
    end
    a = (a - abit) / 2
    b = (b - bbit) / 2
    bit = bit * 2
  end
  return res
end
local construct_nonce
construct_nonce = function(iv, packet_number)
  validate_quic_iv(iv)
  local buf = {
    string.byte(iv, 1, 12)
  }
  local pn = packet_number
  for i = 12, 5, -1 do
    local byte_val = pn % 256
    buf[i] = xor8(buf[i], byte_val)
    pn = (pn - byte_val) / 256
  end
  return string.char((table.unpack or unpack)(buf))
end
local aes_128_gcm_encrypt
aes_128_gcm_encrypt = function(key, nonce, plaintext, aad)
  if aad == nil then
    aad = ""
  end
  validate_gcm_key(key)
  validate_gcm_nonce(nonce)
  local c = get_gcm_tfm("encrypt", key)
  local out = c:encrypt(nonce, plaintext, aad)
  return out
end
local aes_128_gcm_decrypt
aes_128_gcm_decrypt = function(key, nonce, ciphertext_with_tag, aad)
  if aad == nil then
    aad = ""
  end
  assert(#key == 16, "AES-128-GCM key must be 16 bytes (got " .. tostring(#key) .. ")")
  assert(#nonce == 12, "AES-128-GCM nonce must be 12 bytes (got " .. tostring(#nonce) .. ")")
  if #ciphertext_with_tag < 16 then
    return nil, "ciphertext_with_tag too short (need at least 16-byte tag)"
  end
  local c = get_gcm_tfm("decrypt", key)
  local ok, pt_or_err, err = pcall(function()
    return c:decrypt(nonce, ciphertext_with_tag, aad)
  end)
  if not (ok) then
    if (tostring(pt_or_err)):match("EBADMSG") then
      return nil, "AES-128-GCM authentication failed (tag mismatch)"
    end
    error("aead(gcm(aes)) decrypt failed: " .. tostring(tostring(pt_or_err)))
  end
  if pt_or_err == "EBADMSG" then
    return nil, "AES-128-GCM authentication failed (tag mismatch)"
  end
  return pt_or_err, nil
end
local aes_128_ecb_block
aes_128_ecb_block = function(key, block)
  validate_ecb_key(key)
  validate_ecb_block(block)
  local ok, result = pcall(function()
    if not (cached_ecb_tfm) then
      cached_ecb_tfm = skcipher("ecb(aes)")
      cached_ecb_key = nil
    end
    if cached_ecb_key ~= key then
      cached_ecb_tfm:setkey(key)
      cached_ecb_key = key
    end
    return cached_ecb_tfm:encrypt("", block)
  end)
  if not (ok) then
    ecb_fail_streak = ecb_fail_streak + 1
    if ecb_fail_streak == 1 or ecb_fail_streak % 128 == 0 then
      print("WARN: aes_128_ecb_block unavailable (" .. tostring(result) .. "), header protection temporarily skipped [" .. tostring(ecb_fail_streak) .. "]")
    end
    return nil
  end
  ecb_fail_streak = 0
  return result
end
return {
  aes_128_gcm_encrypt = aes_128_gcm_encrypt,
  aes_128_gcm_decrypt = aes_128_gcm_decrypt,
  aes_128_ecb_block = aes_128_ecb_block,
  construct_nonce = construct_nonce
}
