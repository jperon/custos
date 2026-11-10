local ffi = require("ffi")
local GCM_CTX_SIZE = 512
local AES_CTX_SIZE = 512
pcall(ffi.cdef, [[  /* Opaque context structs */
  typedef struct { char _opaque[512]; } mbedtls_gcm_context_t;
  typedef struct { char _opaque[512]; } mbedtls_aes_context_t;

  /* GCM */
  void mbedtls_gcm_init   (mbedtls_gcm_context_t *ctx);
  int  mbedtls_gcm_setkey (mbedtls_gcm_context_t *ctx,
                            int cipher_id,
                            const unsigned char *key,
                            unsigned int keybits);
  int  mbedtls_gcm_crypt_and_tag(
                            mbedtls_gcm_context_t *ctx,
                            int mode,
                            size_t length,
                            const unsigned char *iv,   size_t iv_len,
                            const unsigned char *add,  size_t add_len,
                            const unsigned char *input,
                            unsigned char       *output,
                            size_t tag_len,
                            unsigned char       *tag);
  int  mbedtls_gcm_auth_decrypt(
                            mbedtls_gcm_context_t *ctx,
                            size_t length,
                            const unsigned char *iv,   size_t iv_len,
                            const unsigned char *add,  size_t add_len,
                            const unsigned char *tag,  size_t tag_len,
                            const unsigned char *input,
                            unsigned char       *output);
  void mbedtls_gcm_free   (mbedtls_gcm_context_t *ctx);

  /* AES (ECB) */
  void mbedtls_aes_init       (mbedtls_aes_context_t *ctx);
  int  mbedtls_aes_setkey_enc (mbedtls_aes_context_t *ctx,
                                const unsigned char *key,
                                unsigned int keybits);
  int  mbedtls_aes_crypt_ecb  (mbedtls_aes_context_t *ctx,
                                int mode,
                                const unsigned char input[16],
                                unsigned char       output[16]);
  void mbedtls_aes_free       (mbedtls_aes_context_t *ctx);
]])
local MBEDTLS_CIPHER_ID_AES = 2
local MBEDTLS_GCM_ENCRYPT = 1
local MBEDTLS_AES_ENCRYPT = 1
local MBEDTLS_ERR_GCM_AUTH_FAILED = -18
local mbed = ffi.load("mbedcrypto")
local validate_gcm_key, validate_gcm_nonce, validate_ecb_key, validate_ecb_block, construct_nonce, split_ct_tag
do
  local _obj_0 = require("ipparse.lib.crypto.backend.common")
  validate_gcm_key, validate_gcm_nonce, validate_ecb_key, validate_ecb_block, construct_nonce, split_ct_tag = _obj_0.validate_gcm_key, _obj_0.validate_gcm_nonce, _obj_0.validate_ecb_key, _obj_0.validate_ecb_block, _obj_0.construct_nonce, _obj_0.split_ct_tag
end
local str_to_buf
str_to_buf = function(s)
  local n = #s
  local buf = ffi.new("uint8_t[?]", n + 1)
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
  local ctx = ffi.new("mbedtls_gcm_context_t")
  mbed.mbedtls_gcm_init(ctx)
  local rc = mbed.mbedtls_gcm_setkey(ctx, MBEDTLS_CIPHER_ID_AES, key, 128)
  if rc ~= 0 then
    mbed.mbedtls_gcm_free(ctx)
    return nil, "mbedtls_gcm_setkey failed (" .. tostring(rc) .. ")"
  end
  local out_buf = ffi.new("uint8_t[?]", pt_len + 1)
  local tag_buf = ffi.new("uint8_t[16]")
  rc = mbed.mbedtls_gcm_crypt_and_tag(ctx, MBEDTLS_GCM_ENCRYPT, pt_len, nonce, 12, aad_buf, aad_len, pt_buf, out_buf, 16, tag_buf)
  mbed.mbedtls_gcm_free(ctx)
  if rc ~= 0 then
    return nil, "mbedtls_gcm_crypt_and_tag failed (" .. tostring(rc) .. ")"
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
  local ctx = ffi.new("mbedtls_gcm_context_t")
  mbed.mbedtls_gcm_init(ctx)
  local rc = mbed.mbedtls_gcm_setkey(ctx, MBEDTLS_CIPHER_ID_AES, key, 128)
  if rc ~= 0 then
    mbed.mbedtls_gcm_free(ctx)
    return nil, "mbedtls_gcm_setkey failed (" .. tostring(rc) .. ")"
  end
  local out_buf = ffi.new("uint8_t[?]", ct_len + 1)
  local tag_buf = ffi.new("uint8_t[16]")
  ffi.copy(tag_buf, tag, 16)
  rc = mbed.mbedtls_gcm_auth_decrypt(ctx, ct_len, nonce, 12, aad_buf, aad_len, tag_buf, 16, ct_buf, out_buf)
  mbed.mbedtls_gcm_free(ctx)
  if rc == MBEDTLS_ERR_GCM_AUTH_FAILED then
    return nil, "AES-128-GCM authentication failed (tag mismatch)"
  end
  if rc ~= 0 then
    return nil, "mbedtls_gcm_auth_decrypt failed (" .. tostring(rc) .. ")"
  end
  return ffi.string(out_buf, ct_len)
end
local aes_128_ecb_block
aes_128_ecb_block = function(key, block)
  validate_ecb_key(key)
  validate_ecb_block(block)
  local ctx = ffi.new("mbedtls_aes_context_t")
  mbed.mbedtls_aes_init(ctx)
  local rc = mbed.mbedtls_aes_setkey_enc(ctx, key, 128)
  if rc ~= 0 then
    mbed.mbedtls_aes_free(ctx)
    return nil, "mbedtls_aes_setkey_enc failed (" .. tostring(rc) .. ")"
  end
  local out_buf = ffi.new("uint8_t[16]")
  rc = mbed.mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, block, out_buf)
  mbed.mbedtls_aes_free(ctx)
  if rc ~= 0 then
    return nil, "mbedtls_aes_crypt_ecb failed (" .. tostring(rc) .. ")"
  end
  return ffi.string(out_buf, 16)
end
return {
  construct_nonce = construct_nonce,
  aes_128_gcm_encrypt = aes_128_gcm_encrypt,
  aes_128_gcm_decrypt = aes_128_gcm_decrypt,
  aes_128_ecb_block = aes_128_ecb_block
}
