local ffi = require("ffi")
pcall(ffi.cdef, [[  typedef struct { char _opaque[1024]; } WC_Aes;

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
local construct_nonce
construct_nonce = function(iv, packet_number)
  assert(#iv == 12, "IV must be 12 bytes")
  local buf = ffi.new("uint8_t[12]")
  ffi.copy(buf, iv, 12)
  local pn = packet_number
  for i = 11, 4, -1 do
    buf[i] = ffi.cast("uint8_t", bit.bxor(buf[i], bit.band(pn, 0xFF)))
    pn = bit.rshift(pn, 8)
  end
  return ffi.string(buf, 12)
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
  assert(#key == 16, "AES-128-GCM key must be 16 bytes")
  assert(#nonce == 12, "AES-128-GCM nonce must be 12 bytes")
  local pt_buf, pt_len = str_to_buf(plaintext)
  local aad_buf, aad_len = str_to_buf(aad)
  local aes = ffi.new("WC_Aes")
  local rc = wssl.wc_AesGcmSetKey(aes, key, 16)
  assert(rc == 0, "wc_AesGcmSetKey failed (" .. tostring(rc) .. ")")
  local out_buf = ffi.new("uint8_t[?]", pt_len + 16)
  local tag_buf = ffi.new("uint8_t[16]")
  rc = wssl.wc_AesGcmEncrypt(aes, out_buf, pt_buf, pt_len, nonce, 12, tag_buf, 16, aad_buf, aad_len)
  assert(rc == 0, "wc_AesGcmEncrypt failed (" .. tostring(rc) .. ")")
  return (ffi.string(out_buf, pt_len)) .. (ffi.string(tag_buf, 16))
end
local aes_128_gcm_decrypt
aes_128_gcm_decrypt = function(key, nonce, ciphertext_with_tag, aad)
  if aad == nil then
    aad = ""
  end
  assert(#key == 16, "AES-128-GCM key must be 16 bytes")
  assert(#nonce == 12, "AES-128-GCM nonce must be 12 bytes")
  if #ciphertext_with_tag < 16 then
    return nil, "ciphertext too short (no room for auth tag)"
  end
  local ciphertext = ciphertext_with_tag:sub(1, #ciphertext_with_tag - 16)
  local tag = ciphertext_with_tag:sub(#ciphertext_with_tag - 15)
  local ct_buf, ct_len = str_to_buf(ciphertext)
  local aad_buf, aad_len = str_to_buf(aad)
  local aes = ffi.new("WC_Aes")
  local rc = wssl.wc_AesGcmSetKey(aes, key, 16)
  assert(rc == 0, "wc_AesGcmSetKey failed (" .. tostring(rc) .. ")")
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
  assert(#key == 16, "AES-128-ECB key must be 16 bytes")
  assert(#block == 16, "AES-128-ECB block must be 16 bytes")
  local out_buf = ffi.new("uint8_t[16]")
  local aes = ffi.new("WC_Aes")
  local rc = wssl.wc_AesSetKey(aes, key, 16, nil, 0)
  assert(rc == 0, "wc_AesSetKey failed (" .. tostring(rc) .. ")")
  rc = wssl.wc_AesEncryptDirect(aes, out_buf, block)
  assert(rc == 0, "wc_AesEncryptDirect failed (" .. tostring(rc) .. ")")
  return ffi.string(out_buf, 16)
end
return {
  construct_nonce = construct_nonce,
  aes_128_gcm_encrypt = aes_128_gcm_encrypt,
  aes_128_gcm_decrypt = aes_128_gcm_decrypt,
  aes_128_ecb_block = aes_128_ecb_block
}
