--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Lunatik crypto backend for ipparse (no FFI).
--
-- Implements the ipparse crypto interface using Lunatik's kernel `crypto` Lua API.
-- Requires a Lunatik runtime with:
--   - require("crypto").aead     (for AES-128-GCM)
--   - require("crypto").skcipher (for AES-128-ECB)
--
-- Implements:
--   aes_128_gcm_encrypt(key, nonce, plaintext, aad) → ciphertext_with_tag
--   aes_128_gcm_decrypt(key, nonce, ciphertext_with_tag, aad) → plaintext | nil, err
--   aes_128_ecb_block(key, block) → encrypted_block
--
-- @module lib.crypto.backend.lunatik

{:aead, :skcipher} = require "crypto"

close_tfm = (tfm) ->
  return unless tfm and tfm.__close
  pcall tfm.__close, tfm

xor8 = (a, b) ->
  res = 0
  bit = 1
  for _ = 1, 8
    abit = a % 2
    bbit = b % 2
    if abit != bbit
      res += bit
    a = (a - abit) / 2
    b = (b - bbit) / 2
    bit *= 2
  res

--- Constructs a QUIC nonce: XOR last 8 bytes of iv with packet_number (big-endian).
-- Uses (a | b) - (a & b) to emulate a XOR b without ~ operator.
-- @tparam string iv 12-byte IV
-- @tparam number packet_number QUIC packet number
-- @treturn string 12-byte nonce
construct_nonce = (iv, packet_number) ->
  assert #iv == 12, "IV must be 12 bytes"
  buf = {string.byte iv, 1, 12}
  pn = packet_number
  for i = 12, 5, -1
    byte_val = pn % 256
    buf[i] = xor8 buf[i], byte_val
    pn = (pn - byte_val) / 256
  string.char (table.unpack or unpack) buf

--- Encrypts with AES-128-GCM.
-- @tparam string key 16-byte key
-- @tparam string nonce 12-byte nonce
-- @tparam string plaintext Data to encrypt
-- @tparam string aad Additional authenticated data (optional)
-- @treturn string ciphertext || tag (16 bytes appended to ciphertext)
aes_128_gcm_encrypt = (key, nonce, plaintext, aad = "") ->
  assert #key == 16, "AES-128-GCM key must be 16 bytes"
  assert #nonce == 12, "AES-128-GCM nonce must be 12 bytes"
  c = aead "gcm(aes)"
  c\setkey key
  c\setauthsize 16
  out = c\encrypt nonce, plaintext, aad
  close_tfm c
  out

--- Decrypts with AES-128-GCM.
-- @tparam string key 16-byte key
-- @tparam string nonce 12-byte nonce
-- @tparam string ciphertext_with_tag Ciphertext with 16-byte tag appended
-- @tparam string aad Additional authenticated data (optional)
-- @treturn string plaintext on success, or nil on authentication failure
-- @treturn string error message on failure
aes_128_gcm_decrypt = (key, nonce, ciphertext_with_tag, aad = "") ->
  assert #key == 16, "AES-128-GCM key must be 16 bytes"
  assert #nonce == 12, "AES-128-GCM nonce must be 12 bytes"
  if #ciphertext_with_tag < 16
    return nil, "ciphertext_with_tag too short (need at least 16-byte tag)"
  c = aead "gcm(aes)"
  c\setkey key
  c\setauthsize 16
  -- Wrap decrypt call to catch EBADMSG as a handled error, not an exception
  ok, pt_or_err, err = pcall -> c\decrypt nonce, ciphertext_with_tag, aad
  close_tfm c
  unless ok
    -- Decrypt failed with Lua error
    if (tostring pt_or_err)\match "EBADMSG"
      return nil, "AES-128-GCM authentication failed (tag mismatch)"
    error "aead(gcm(aes)) decrypt failed: #{tostring pt_or_err}"
  -- ok=true, pt_or_err is plaintext, err is error code
  if pt_or_err == "EBADMSG"
    return nil, "AES-128-GCM authentication failed (tag mismatch)"
  -- pt_or_err is plaintext (may be empty string, which is valid)
  pt_or_err, nil

--- Encrypts single AES-128-ECB block.
-- @tparam string key 16-byte key
-- @tparam string block 16-byte plaintext block
-- @treturn string 16-byte ciphertext block
aes_128_ecb_block = (key, block) ->
  assert #key == 16, "AES-128-ECB key must be 16 bytes"
  assert #block == 16, "AES-128-ECB block must be 16 bytes"
  tfm = skcipher "ecb(aes)"
  tfm\setkey key
  out = tfm\encrypt "", block
  close_tfm tfm
  out

{
  :aes_128_gcm_encrypt
  :aes_128_gcm_decrypt
  :aes_128_ecb_block
  :construct_nonce
}
