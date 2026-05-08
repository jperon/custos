local aead, skcipher
do
  local _obj_0 = require("crypto")
  aead, skcipher = _obj_0.aead, _obj_0.skcipher
end
local close_tfm
close_tfm = function(tfm)
  if not (tfm and tfm.__close) then
    return 
  end
  return pcall(tfm.__close, tfm)
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
  assert(#iv == 12, "IV must be 12 bytes")
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
  assert(#key == 16, "AES-128-GCM key must be 16 bytes")
  assert(#nonce == 12, "AES-128-GCM nonce must be 12 bytes")
  local c = aead("gcm(aes)")
  c:setkey(key)
  c:setauthsize(16)
  local out = c:encrypt(nonce, plaintext, aad)
  close_tfm(c)
  return out
end
local aes_128_gcm_decrypt
aes_128_gcm_decrypt = function(key, nonce, ciphertext_with_tag, aad)
  if aad == nil then
    aad = ""
  end
  assert(#key == 16, "AES-128-GCM key must be 16 bytes")
  assert(#nonce == 12, "AES-128-GCM nonce must be 12 bytes")
  if #ciphertext_with_tag < 16 then
    return nil, "ciphertext_with_tag too short (need at least 16-byte tag)"
  end
  local c = aead("gcm(aes)")
  c:setkey(key)
  c:setauthsize(16)
  local ok, pt_or_err, err = pcall(function()
    return c:decrypt(nonce, ciphertext_with_tag, aad)
  end)
  close_tfm(c)
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
  assert(#key == 16, "AES-128-ECB key must be 16 bytes")
  assert(#block == 16, "AES-128-ECB block must be 16 bytes")
  local tfm = skcipher("ecb(aes)")
  tfm:setkey(key)
  local out = tfm:encrypt("", block)
  close_tfm(tfm)
  return out
end
return {
  aes_128_gcm_encrypt = aes_128_gcm_encrypt,
  aes_128_gcm_decrypt = aes_128_gcm_decrypt,
  aes_128_ecb_block = aes_128_ecb_block,
  construct_nonce = construct_nonce
}
