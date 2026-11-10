local ffi = require("ffi")
local validate_gcm_key, validate_gcm_nonce, validate_ecb_key, validate_ecb_block, construct_nonce, split_ct_tag
do
  local _obj_0 = require("ipparse.lib.crypto.backend.common")
  validate_gcm_key, validate_gcm_nonce, validate_ecb_key, validate_ecb_block, construct_nonce, split_ct_tag = _obj_0.validate_gcm_key, _obj_0.validate_gcm_nonce, _obj_0.validate_ecb_key, _obj_0.validate_ecb_block, _obj_0.construct_nonce, _obj_0.split_ct_tag
end
pcall(ffi.cdef, [[  typedef struct { char _opaque[4096]; } WC_Aes;

  int wc_AesGcmSetKey (WC_Aes *aes, const unsigned char *key, unsigned int keySz);
  int wc_AesGcmEncrypt(WC_Aes *aes,
                       unsigned char *out, const unsigned char *in, unsigned int sz,
                       const unsigned char *iv, unsigned int ivSz,
                       unsigned char *authTag, unsigned int authTagSz,
                       const unsigned char *authIn, unsigned int authInSz);
  int wc_AesGcmDecrypt(WC_Aes *aes,
                       unsigned char *out, const unsigned char *in, unsigned int sz,
                       const unsigned char *iv, unsigned int ivSz,
                       const unsigned char *authTag, unsigned int authTagSz,
                       const unsigned char *authIn, unsigned int authInSz);
]])
pcall(ffi.cdef, [[  int wc_AesSetKey(WC_Aes *aes, const unsigned char *key, unsigned int keySz,
                   const unsigned char *iv, int dir);
  int wc_AesEncryptDirect(WC_Aes *aes, unsigned char *out, const unsigned char *in);
]])
local load_wolfssl
load_wolfssl = function()
  local candidates = {
    "wolfssl",
    "libwolfssl",
    "libwolfssl.so"
  }
  local seen = { }
  for _index_0 = 1, #candidates do
    local name = candidates[_index_0]
    seen[name] = true
  end
  if io and io.popen then
    local _list_0 = {
      "/usr/lib",
      "/lib",
      "/usr/local/lib"
    }
    for _index_0 = 1, #_list_0 do
      local dir = _list_0[_index_0]
      local cmd = "ls -1 " .. tostring(dir) .. "/libwolfssl.so* 2>/dev/null"
      local p = io.popen(cmd)
      if p then
        for line in p:lines() do
          if line and #line > 0 and not seen[line] then
            candidates[#candidates + 1] = line
            seen[line] = true
          end
        end
        p:close()
      end
    end
  end
  local last_err = nil
  for _index_0 = 1, #candidates do
    local name = candidates[_index_0]
    local ok, lib = pcall(ffi.load, name)
    if ok and lib then
      return lib
    end
    last_err = lib
  end
  return error("ffi_wolfssl: cannot load wolfssl library (tried " .. tostring(table.concat(candidates, ', ')) .. "): " .. tostring(last_err))
end
local wssl = load_wolfssl()
local direct_ecb_available = (pcall(function()
  return wssl.wc_AesSetKey
end)) and (pcall(function()
  return wssl.wc_AesEncryptDirect
end))
if not (direct_ecb_available) then
  error("ffi_wolfssl: no AES-128-ECB implementation available (missing wc_AesSetKey/wc_AesEncryptDirect)")
end
local str_to_buf
str_to_buf = function(s)
  local n = #s
  local buf = ffi.new("uint8_t[?]", n + 32)
  if n > 0 then
    ffi.copy(buf, s, n)
  end
  return buf, n
end
local aes_128_gcm_encrypt
aes_128_gcm_encrypt = function(key, nonce, plaintext, aad)
  if aad == nil then
    aad = ""
  end
  validate_gcm_key(key)
  validate_gcm_nonce(nonce)
  local pt_buf, pt_len = str_to_buf(plaintext)
  local aad_buf, aad_len = str_to_buf(aad)
  local aes = ffi.new("WC_Aes")
  local rc = wssl.wc_AesGcmSetKey(aes, key, 16)
  if rc ~= 0 then
    return nil, "wc_AesGcmSetKey failed (" .. tostring(rc) .. ")"
  end
  local out_buf = ffi.new("uint8_t[?]", pt_len + 16)
  local tag_buf = ffi.new("uint8_t[16]")
  rc = wssl.wc_AesGcmEncrypt(aes, out_buf, pt_buf, pt_len, nonce, 12, tag_buf, 16, aad_buf, aad_len)
  if rc ~= 0 then
    return nil, "wc_AesGcmEncrypt failed (" .. tostring(rc) .. ")"
  end
  return (ffi.string(out_buf, pt_len)) .. (ffi.string(tag_buf, 16))
end
local aes_128_gcm_decrypt
aes_128_gcm_decrypt = function(key, nonce, ciphertext_with_tag, aad)
  if aad == nil then
    aad = ""
  end
  validate_gcm_key(key)
  validate_gcm_nonce(nonce)
  local ciphertext, tag = split_ct_tag(ciphertext_with_tag)
  if not (ciphertext) then
    return nil, tag
  end
  local ct_buf, ct_len = str_to_buf(ciphertext)
  local aad_buf, aad_len = str_to_buf(aad)
  local aes = ffi.new("WC_Aes")
  local rc = wssl.wc_AesGcmSetKey(aes, key, 16)
  if rc ~= 0 then
    return nil, "wc_AesGcmSetKey failed (" .. tostring(rc) .. ")"
  end
  local out_buf = ffi.new("uint8_t[?]", ct_len + 1)
  local tag_buf = ffi.new("uint8_t[16]")
  ffi.copy(tag_buf, tag, 16)
  rc = wssl.wc_AesGcmDecrypt(aes, out_buf, ct_buf, ct_len, nonce, 12, tag_buf, 16, aad_buf, aad_len)
  if rc ~= 0 then
    return nil, "AES-128-GCM authentication failed (tag mismatch)"
  end
  return ffi.string(out_buf, ct_len)
end
local aes_128_ecb_block
aes_128_ecb_block = function(key, block)
  validate_ecb_key(key)
  validate_ecb_block(block)
  local out_buf = ffi.new("uint8_t[16]")
  local aes = ffi.new("WC_Aes")
  local rc = wssl.wc_AesSetKey(aes, key, 16, nil, 0)
  if rc ~= 0 then
    return nil, "wc_AesSetKey failed (" .. tostring(rc) .. ")"
  end
  rc = wssl.wc_AesEncryptDirect(aes, out_buf, block)
  if rc ~= 0 then
    return nil, "wc_AesEncryptDirect failed (" .. tostring(rc) .. ")"
  end
  return ffi.string(out_buf, 16)
end
return {
  construct_nonce = construct_nonce,
  aes_128_gcm_encrypt = aes_128_gcm_encrypt,
  aes_128_gcm_decrypt = aes_128_gcm_decrypt,
  aes_128_ecb_block = aes_128_ecb_block
}
