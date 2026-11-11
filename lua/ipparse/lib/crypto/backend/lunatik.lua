local aead, skcipher
do
  local _obj_0 = require("crypto")
  aead, skcipher = _obj_0.aead, _obj_0.skcipher
end
local validate_gcm_key, validate_gcm_nonce, validate_ecb_key, validate_ecb_block, construct_nonce
do
  local _obj_0 = require("ipparse.lib.crypto.backend.common")
  validate_gcm_key, validate_gcm_nonce, validate_ecb_key, validate_ecb_block, construct_nonce = _obj_0.validate_gcm_key, _obj_0.validate_gcm_nonce, _obj_0.validate_ecb_key, _obj_0.validate_ecb_block, _obj_0.construct_nonce
end
local ebadmsg_names = {
  EBADMSG = true,
  ["-EBADMSG"] = true,
  ["-74"] = true
}
local is_ebadmsg
is_ebadmsg = function(err)
  local s = tostring(err)
  local bare = (s:match("^.*:%d+: (.*)$")) or s
  return ebadmsg_names[bare] == true
end
local ebadmsg_error
ebadmsg_error = function(err)
  if not (is_ebadmsg(err)) then
    return 
  end
  return "AES-128-GCM authentication failed (tag mismatch)"
end
local gcm_cache = {
  encrypt = { },
  decrypt = { }
}
local cached_ecb_tfm = nil
local cached_ecb_key = nil
local ecb_fail_streak = 0
local get_gcm_tfm
get_gcm_tfm = function(mode, key)
  local entry = gcm_cache[mode]
  if not (entry.tfm) then
    entry.tfm = aead("gcm(aes)")
    entry.tfm:setauthsize(16)
  end
  if entry.key ~= key then
    entry.tfm:setkey(key)
    entry.key = key
  end
  return entry.tfm
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
  validate_gcm_key(key)
  validate_gcm_nonce(nonce)
  if #ciphertext_with_tag < 16 then
    return nil, "ciphertext_with_tag too short (need at least 16-byte tag)"
  end
  local c = get_gcm_tfm("decrypt", key)
  local ok, pt, err = pcall(c.decrypt, c, nonce, ciphertext_with_tag, aad)
  if not (ok) then
    local msg = ebadmsg_error(pt)
    if msg then
      return nil, msg
    end
    return nil, "aead(gcm(aes)) decrypt failed: " .. tostring(tostring(pt))
  end
  if pt == nil then
    local msg = ebadmsg_error(err)
    if msg then
      return nil, msg
    end
    return nil, "aead(gcm(aes)) decrypt failed: " .. tostring(tostring(err))
  end
  return pt, nil
end
local ecb_encrypt
ecb_encrypt = function(key, block)
  if not (cached_ecb_tfm) then
    cached_ecb_tfm = skcipher("ecb(aes)")
    cached_ecb_key = nil
  end
  if cached_ecb_key ~= key then
    cached_ecb_tfm:setkey(key)
    cached_ecb_key = key
  end
  return cached_ecb_tfm:encrypt("", block)
end
local aes_128_ecb_block
aes_128_ecb_block = function(key, block)
  validate_ecb_key(key)
  validate_ecb_block(block)
  local ok, result = pcall(ecb_encrypt, key, block)
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
