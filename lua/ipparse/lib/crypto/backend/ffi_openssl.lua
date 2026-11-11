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

  int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *c, int pad);
]])
local EVP_CTRL_GCM_SET_IVLEN = 0x9
local EVP_CTRL_GCM_GET_TAG = 0x10
local EVP_CTRL_GCM_SET_TAG = 0x11
local ssl = ffi.load("crypto")
local validate_gcm_key, validate_gcm_nonce, validate_ecb_key, validate_ecb_block, construct_nonce, split_ct_tag
do
  local _obj_0 = require("ipparse.lib.crypto.backend.common")
  validate_gcm_key, validate_gcm_nonce, validate_ecb_key, validate_ecb_block, construct_nonce, split_ct_tag = _obj_0.validate_gcm_key, _obj_0.validate_gcm_nonce, _obj_0.validate_ecb_key, _obj_0.validate_ecb_block, _obj_0.construct_nonce, _obj_0.split_ct_tag
end
local fail
fail = function(ctx, msg)
  if ctx ~= nil then
    ssl.EVP_CIPHER_CTX_free(ctx)
  end
  return nil, msg
end
local aes_128_gcm_encrypt
aes_128_gcm_encrypt = function(key, nonce, plaintext, aad)
  if aad == nil then
    aad = ""
  end
  validate_gcm_key(key)
  validate_gcm_nonce(nonce)
  local ctx = ssl.EVP_CIPHER_CTX_new()
  if ctx == nil then
    return fail(nil, "EVP_CIPHER_CTX_new failed")
  end
  if not (1 == ssl.EVP_EncryptInit_ex(ctx, ssl.EVP_aes_128_gcm(), nil, nil, nil)) then
    return fail(ctx, "EVP_EncryptInit_ex (cipher) failed")
  end
  if not (1 == ssl.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nil)) then
    return fail(ctx, "EVP_CTRL_GCM_SET_IVLEN failed")
  end
  if not (1 == ssl.EVP_EncryptInit_ex(ctx, nil, nil, key, nonce)) then
    return fail(ctx, "EVP_EncryptInit_ex (key/nonce) failed")
  end
  local outl = ffi.new("int[1]")
  if #aad > 0 then
    if not (1 == ssl.EVP_EncryptUpdate(ctx, nil, outl, aad, #aad)) then
      return fail(ctx, "EVP_EncryptUpdate (AAD) failed")
    end
  end
  local ciphertext_buf = ffi.new("uint8_t[?]", #plaintext + 16)
  if not (1 == ssl.EVP_EncryptUpdate(ctx, ciphertext_buf, outl, plaintext, #plaintext)) then
    return fail(ctx, "EVP_EncryptUpdate (plaintext) failed")
  end
  local ciphertext_len = outl[0]
  local final_buf = ffi.new("uint8_t[16]")
  if not (1 == ssl.EVP_EncryptFinal_ex(ctx, final_buf, outl)) then
    return fail(ctx, "EVP_EncryptFinal_ex failed")
  end
  ciphertext_len = ciphertext_len + outl[0]
  local tag_buf = ffi.new("uint8_t[16]")
  if not (1 == ssl.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_buf)) then
    return fail(ctx, "EVP_CTRL_GCM_GET_TAG failed")
  end
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
  local ciphertext, tag = split_ct_tag(ciphertext_with_tag)
  if not (ciphertext) then
    return nil, tag
  end
  local ctx = ssl.EVP_CIPHER_CTX_new()
  if ctx == nil then
    return fail(nil, "EVP_CIPHER_CTX_new failed")
  end
  if not (1 == ssl.EVP_DecryptInit_ex(ctx, ssl.EVP_aes_128_gcm(), nil, nil, nil)) then
    return fail(ctx, "EVP_DecryptInit_ex (cipher) failed")
  end
  if not (1 == ssl.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nil)) then
    return fail(ctx, "EVP_CTRL_GCM_SET_IVLEN failed")
  end
  if not (1 == ssl.EVP_DecryptInit_ex(ctx, nil, nil, key, nonce)) then
    return fail(ctx, "EVP_DecryptInit_ex (key/nonce) failed")
  end
  local outl = ffi.new("int[1]")
  if #aad > 0 then
    if not (1 == ssl.EVP_DecryptUpdate(ctx, nil, outl, aad, #aad)) then
      return fail(ctx, "EVP_DecryptUpdate (AAD) failed")
    end
  end
  local plaintext_buf = ffi.new("uint8_t[?]", #ciphertext + 16)
  if not (1 == ssl.EVP_DecryptUpdate(ctx, plaintext_buf, outl, ciphertext, #ciphertext)) then
    return fail(ctx, "EVP_DecryptUpdate (ciphertext) failed")
  end
  local plaintext_len = outl[0]
  local tag_buf = ffi.new("uint8_t[16]")
  ffi.copy(tag_buf, tag, 16)
  if not (1 == ssl.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag_buf)) then
    return fail(ctx, "EVP_CTRL_GCM_SET_TAG failed")
  end
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
  if ctx == nil then
    return fail(nil, "EVP_CIPHER_CTX_new failed")
  end
  if not (1 == ssl.EVP_EncryptInit_ex(ctx, ssl.EVP_aes_128_ecb(), nil, key, nil)) then
    return fail(ctx, "EVP_EncryptInit_ex (ECB) failed")
  end
  ssl.EVP_CIPHER_CTX_set_padding(ctx, 0)
  local outl = ffi.new("int[1]")
  local out_buf = ffi.new("uint8_t[32]")
  if not (1 == ssl.EVP_EncryptUpdate(ctx, out_buf, outl, block, 16)) then
    return fail(ctx, "EVP_EncryptUpdate (ECB) failed")
  end
  local len = outl[0]
  local final_buf = ffi.new("uint8_t[16]")
  if not (1 == ssl.EVP_EncryptFinal_ex(ctx, final_buf, outl)) then
    return fail(ctx, "EVP_EncryptFinal_ex (ECB) failed")
  end
  len = len + outl[0]
  ssl.EVP_CIPHER_CTX_free(ctx)
  if len ~= 16 then
    return nil, "AES-128-ECB output length mismatch: expected 16, got " .. tostring(len)
  end
  return ffi.string(out_buf, 16)
end
return {
  construct_nonce = construct_nonce,
  aes_128_gcm_encrypt = aes_128_gcm_encrypt,
  aes_128_gcm_decrypt = aes_128_gcm_decrypt,
  aes_128_ecb_block = aes_128_ecb_block
}
