local ffi = require("ffi")
ffi.cdef([[  /* EVP generic */
  typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
  typedef struct evp_cipher_st     EVP_CIPHER;

  EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
  void            EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
  int             EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

  const EVP_CIPHER *EVP_aes_128_gcm(void);
  const EVP_CIPHER *EVP_aes_128_ecb(void);

  int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                         void *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
  int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

  int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                         void *impl, const unsigned char *key, const unsigned char *iv);
  int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
]])
local EVP_CTRL_GCM_SET_IVLEN = 0x9
local EVP_CTRL_GCM_GET_TAG = 0x10
local EVP_CTRL_GCM_SET_TAG = 0x11
local ssl = ffi.load("crypto")
local validate_gcm_key, validate_gcm_nonce, validate_ecb_key, validate_ecb_block, validate_quic_iv
do
  local _obj_0 = require("ipparse.lib.crypto.backend.common")
  validate_gcm_key, validate_gcm_nonce, validate_ecb_key, validate_ecb_block, validate_quic_iv = _obj_0.validate_gcm_key, _obj_0.validate_gcm_nonce, _obj_0.validate_ecb_key, _obj_0.validate_ecb_block, _obj_0.validate_quic_iv
end
local construct_nonce
construct_nonce = function(iv, packet_number)
  validate_quic_iv(iv)
  local buf = ffi.new("uint8_t[12]")
  ffi.copy(buf, iv, 12)
  local pn = packet_number
  for i = 11, 4, -1 do
    buf[i] = ffi.cast("uint8_t", bit.bxor(buf[i], bit.band(pn, 0xFF)))
    pn = bit.rshift(pn, 8)
  end
  return ffi.string(buf, 12)
end
local aes_128_gcm_encrypt
aes_128_gcm_encrypt = function(key, nonce, plaintext, aad)
  if aad == nil then
    aad = ""
  end
  validate_gcm_key(key)
  validate_gcm_nonce(nonce)
  local ctx = ssl.EVP_CIPHER_CTX_new()
  assert(ctx ~= nil, "EVP_CIPHER_CTX_new failed")
  local ok = ssl.EVP_EncryptInit_ex(ctx, ssl.EVP_aes_128_gcm(), nil, nil, nil)
  assert(ok == 1, "EVP_EncryptInit_ex (cipher) failed")
  ok = ssl.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nil)
  assert(ok == 1, "EVP_CTRL_GCM_SET_IVLEN failed")
  ok = ssl.EVP_EncryptInit_ex(ctx, nil, nil, key, nonce)
  assert(ok == 1, "EVP_EncryptInit_ex (key/nonce) failed")
  local outl = ffi.new("int[1]")
  if #aad > 0 then
    ok = ssl.EVP_EncryptUpdate(ctx, nil, outl, aad, #aad)
    assert(ok == 1, "EVP_EncryptUpdate (AAD) failed")
  end
  local ciphertext_buf = ffi.new("uint8_t[?]", #plaintext + 16)
  ok = ssl.EVP_EncryptUpdate(ctx, ciphertext_buf, outl, plaintext, #plaintext)
  assert(ok == 1, "EVP_EncryptUpdate (plaintext) failed")
  local ciphertext_len = outl[0]
  local final_buf = ffi.new("uint8_t[16]")
  ok = ssl.EVP_EncryptFinal_ex(ctx, final_buf, outl)
  assert(ok == 1, "EVP_EncryptFinal_ex failed")
  ciphertext_len = ciphertext_len + outl[0]
  local tag_buf = ffi.new("uint8_t[16]")
  ok = ssl.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_buf)
  assert(ok == 1, "EVP_CTRL_GCM_GET_TAG failed")
  ssl.EVP_CIPHER_CTX_free(ctx)
  return (ffi.string(ciphertext_buf, ciphertext_len)) .. (ffi.string(tag_buf, 16))
end
local aes_128_gcm_decrypt
aes_128_gcm_decrypt = function(key, nonce, ciphertext_with_tag, aad)
  if aad == nil then
    aad = ""
  end
  validate_gcm_key(key)
  validate_gcm_nonce(nonce)
  if #ciphertext_with_tag < 16 then
    return nil, "ciphertext too short (no room for auth tag)"
  end
  local ciphertext = ciphertext_with_tag:sub(1, #ciphertext_with_tag - 16)
  local tag = ciphertext_with_tag:sub(#ciphertext_with_tag - 15)
  local ctx = ssl.EVP_CIPHER_CTX_new()
  assert(ctx ~= nil, "EVP_CIPHER_CTX_new failed")
  local ok = ssl.EVP_DecryptInit_ex(ctx, ssl.EVP_aes_128_gcm(), nil, nil, nil)
  assert(ok == 1, "EVP_DecryptInit_ex (cipher) failed")
  ok = ssl.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nil)
  assert(ok == 1, "EVP_CTRL_GCM_SET_IVLEN failed")
  ok = ssl.EVP_DecryptInit_ex(ctx, nil, nil, key, nonce)
  assert(ok == 1, "EVP_DecryptInit_ex (key/nonce) failed")
  local outl = ffi.new("int[1]")
  if #aad > 0 then
    ok = ssl.EVP_DecryptUpdate(ctx, nil, outl, aad, #aad)
    assert(ok == 1, "EVP_DecryptUpdate (AAD) failed")
  end
  local plaintext_buf = ffi.new("uint8_t[?]", #ciphertext + 16)
  ok = ssl.EVP_DecryptUpdate(ctx, plaintext_buf, outl, ciphertext, #ciphertext)
  assert(ok == 1, "EVP_DecryptUpdate (ciphertext) failed")
  local plaintext_len = outl[0]
  local tag_buf = ffi.new("uint8_t[16]")
  ffi.copy(tag_buf, tag, 16)
  ok = ssl.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag_buf)
  assert(ok == 1, "EVP_CTRL_GCM_SET_TAG failed")
  local final_buf = ffi.new("uint8_t[16]")
  local rc = ssl.EVP_DecryptFinal_ex(ctx, final_buf, outl)
  ssl.EVP_CIPHER_CTX_free(ctx)
  if rc ~= 1 then
    return nil, "AES-128-GCM authentication failed (tag mismatch)"
  end
  plaintext_len = plaintext_len + outl[0]
  return ffi.string(plaintext_buf, plaintext_len)
end
local aes_128_ecb_block
aes_128_ecb_block = function(key, block)
  validate_ecb_key(key)
  validate_ecb_block(block)
  local ctx = ssl.EVP_CIPHER_CTX_new()
  assert(ctx ~= nil, "EVP_CIPHER_CTX_new failed")
  local ok = ssl.EVP_EncryptInit_ex(ctx, ssl.EVP_aes_128_ecb(), nil, key, nil)
  assert(ok == 1, "EVP_EncryptInit_ex (ECB) failed")
  if not pcall(function()
    return ffi.C.EVP_CIPHER_CTX_set_padding
  end) then
    ffi.cdef("int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);")
  end
  ssl.EVP_CIPHER_CTX_set_padding(ctx, 0)
  local outl = ffi.new("int[1]")
  local out_buf = ffi.new("uint8_t[32]")
  ok = ssl.EVP_EncryptUpdate(ctx, out_buf, outl, block, 16)
  assert(ok == 1, "EVP_EncryptUpdate (ECB) failed")
  local len = outl[0]
  local final_buf = ffi.new("uint8_t[16]")
  ok = ssl.EVP_EncryptFinal_ex(ctx, final_buf, outl)
  assert(ok == 1, "EVP_EncryptFinal_ex (ECB) failed")
  len = len + outl[0]
  ssl.EVP_CIPHER_CTX_free(ctx)
  assert(len == 16, "AES-128-ECB output length mismatch: expected 16, got " .. tostring(len))
  return ffi.string(out_buf, 16)
end
return {
  construct_nonce = construct_nonce,
  aes_128_gcm_encrypt = aes_128_gcm_encrypt,
  aes_128_gcm_decrypt = aes_128_gcm_decrypt,
  aes_128_ecb_block = aes_128_ecb_block
}
