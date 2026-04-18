--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Real AEAD Implementation for QUIC
-- This module provides real AES-GCM encryption/decryption using the existing
-- OpenSSL-based crypto library for QUIC packet protection.

pack: sp, unpack: su = require "ipparse.lib.pack_compat"
:bin2hex, :hex2bin = require "ipparse.init"
{:band, :bor, :bnot, :lshift, :rshift} = require "ipparse.lib.bit_compat"

-- Try to load the real crypto.aead module
local real_aead
crypto_available = false

-- Try different paths to find the crypto module
success, aead_module = pcall(require, "ipparse.lib.crypto.aead")
if success
  real_aead = aead_module
  crypto_available = true
else
  -- Try the compiled lua version
  success, lua_aead = pcall(dofile, "lib/crypto/aead.lua")
  if success
    real_aead = lua_aead
    crypto_available = true
  else
    -- Try from parent directory
    success, parent_aead = pcall(dofile, "../lib/crypto/aead.lua")
    if success
      real_aead = parent_aead
      crypto_available = true

unless crypto_available
  print "Warning: Real crypto not available, falling back to stub implementation"

-- Use the same XOR workaround as before
xor = (a, b) -> band(bor(a, b), bnot(band(a, b)))

--- AEAD algorithm identifiers
aead_algorithms = {
  AES_128_GCM: "AES-128-GCM"
  AES_256_GCM: "AES-256-GCM"
  CHACHA20_POLY1305: "ChaCha20-Poly1305"
}

--- Constructs a QUIC nonce from IV and packet number
-- @tparam string iv The initialization vector (12 bytes for GCM)
-- @tparam number packet_number The QUIC packet number
-- @treturn string The constructed nonce (12 bytes)
construct_nonce = (iv, packet_number) ->
  -- Ensure IV is 12 bytes
  if #iv != 12
    error "IV must be 12 bytes for QUIC AEAD"

  -- Convert packet number to 8-byte big-endian integer
  pn_bytes = sp ">I8", packet_number

  -- XOR the last 8 bytes of IV with packet number
  nonce = iv\sub(1, 4)  -- First 4 bytes unchanged
  for i = 1, 8
    iv_byte = su "B", iv, 4 + i
    pn_byte = su "B", pn_bytes, i
    nonce ..= sp "B", xor iv_byte, pn_byte

  nonce

--- Real AES-128-GCM encryption using OpenSSL
-- @tparam string key The encryption key (16 bytes)
-- @tparam string nonce The nonce (12 bytes)
-- @tparam string plaintext The data to encrypt
-- @tparam string aad Additional authenticated data
-- @treturn string Encrypted ciphertext + authentication tag
real_aes_128_gcm_encrypt = (key, nonce, plaintext, aad="") ->
  unless #key == 16
    error "AES-128-GCM key must be 16 bytes"
  unless #nonce == 12
    error "AES-GCM nonce must be 12 bytes"

  if crypto_available and real_aead
    -- Use real OpenSSL-based crypto
    cipher = real_aead.new "gcm(aes)"
    cipher\setkey key
    cipher\setauthsize 16

    result = cipher\encrypt nonce, plaintext, aad
    return result
  else
    -- Fallback to stub implementation
    return stub_aes_gcm_encrypt key, nonce, plaintext, aad

--- Real AES-128-GCM decryption using OpenSSL
-- @tparam string key The decryption key (16 bytes)
-- @tparam string nonce The nonce (12 bytes)
-- @tparam string ciphertext_with_tag The encrypted data with authentication tag
-- @tparam string aad Additional authenticated data
-- @treturn string Decrypted plaintext, or nil if authentication fails
real_aes_128_gcm_decrypt = (key, nonce, ciphertext_with_tag, aad="") ->
  unless #key == 16
    error "AES-128-GCM key must be 16 bytes"
  unless #nonce == 12
    error "AES-GCM nonce must be 12 bytes"
  unless #ciphertext_with_tag >= 16
    return nil

  if crypto_available and real_aead
    -- Use real OpenSSL-based crypto
    cipher = real_aead.new "gcm(aes)"
    cipher\setkey key
    cipher\setauthsize 16

    result, err = cipher\decrypt nonce, ciphertext_with_tag, aad
    return result
  else
    -- Fallback to stub implementation
    return stub_aes_gcm_decrypt key, nonce, ciphertext_with_tag, aad

--- Stub implementations (same as before for fallback)
stub_aes_gcm_encrypt = (key, nonce, plaintext, aad="") ->
  unless #key == 16
    error "AES-128-GCM key must be 16 bytes"
  unless #nonce == 12
    error "AES-GCM nonce must be 12 bytes"

  -- Simple XOR cipher for testing (NOT secure!)
  ciphertext = ""
  for i = 1, #plaintext
    p = string.byte(plaintext, i)
    k = string.byte(key, ((i - 1) % #key) + 1)
    ciphertext = ciphertext .. string.char(xor p, k)

  -- Generate fake 16-byte authentication tag
  auth_tag = ""
  for i = 1, 16
    k = string.byte(key, ((i - 1) % #key) + 1)
    n = string.byte(nonce, ((i - 1) % #nonce) + 1)
    auth_tag = auth_tag .. string.char(xor k, n)

  ciphertext .. auth_tag

stub_aes_gcm_decrypt = (key, nonce, ciphertext_with_tag, aad="") ->
  unless #key == 16
    error "AES-128-GCM key must be 16 bytes"
  unless #nonce == 12
    error "AES-GCM nonce must be 12 bytes"
  unless #ciphertext_with_tag >= 16
    return nil

  -- Split ciphertext and authentication tag
  ciphertext = ciphertext_with_tag\sub 1, #ciphertext_with_tag - 16
  received_tag = ciphertext_with_tag\sub #ciphertext_with_tag - 15

  -- Generate expected authentication tag (same as encrypt)
  expected_tag = ""
  for i = 1, 16
    k = string.byte(key, ((i - 1) % #key) + 1)
    n = string.byte(nonce, ((i - 1) % #nonce) + 1)
    expected_tag = expected_tag .. string.char(xor k, n)

  -- Verify authentication tag
  if received_tag != expected_tag
    return nil

  -- Decrypt by XORing with key bytes (reverse of encrypt)
  plaintext = ""
  for i = 1, #ciphertext
    c = string.byte(ciphertext, i)
    k = string.byte(key, ((i - 1) % #key) + 1)
    plaintext = plaintext .. string.char(xor c, k)

  plaintext

--- Main AES-128-GCM functions (use real crypto when available)
aes_128_gcm_encrypt = real_aes_gcm_encrypt
aes_128_gcm_decrypt = real_aes_128_gcm_decrypt

--- Generic AEAD encryption interface
aead_encrypt = (algorithm, key, nonce, plaintext, aad="") ->
  switch algorithm
    when "AES-128-GCM"
      aes_128_gcm_encrypt key, nonce, plaintext, aad
    else
      error "Unsupported AEAD algorithm: #{algorithm}"

--- Generic AEAD decryption interface
aead_decrypt = (algorithm, key, nonce, ciphertext_with_tag, aad="") ->
  switch algorithm
    when "AES-128-GCM"
      aes_128_gcm_decrypt key, nonce, ciphertext_with_tag, aad
    else
      error "Unsupported AEAD algorithm: #{algorithm}"

--- QUIC-specific packet protection encryption
quic_encrypt_packet = (key, iv, packet_number, plaintext, header_aad) ->
  nonce = construct_nonce iv, packet_number
  aes_128_gcm_encrypt key, nonce, plaintext, header_aad

--- QUIC-specific packet protection decryption
quic_decrypt_packet = (key, iv, packet_number, ciphertext_with_tag, header_aad) ->
  nonce = construct_nonce iv, packet_number
  aes_128_gcm_decrypt key, nonce, ciphertext_with_tag, header_aad

{
  :aead_encrypt, :aead_decrypt, :aes_128_gcm_encrypt, :aes_128_gcm_decrypt,
  :construct_nonce, :quic_encrypt_packet, :quic_decrypt_packet, :aead_algorithms, :crypto_available
}
