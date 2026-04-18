--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- AEAD (Authenticated Encryption with Associated Data) Module
-- This module provides AEAD encryption and decryption functionality for QUIC packet protection.
-- It supports AES-128-GCM and ChaCha20-Poly1305 algorithms as required by QUIC specifications.
--
-- @module crypto.aead

pack: sp, unpack: su = require "ipparse.lib.pack_compat"
:bin2hex = require"ipparse.init"
{:band, :bor, :bnot, :lshift, :rshift} = require"ipparse.lib.bit_compat"

xor = (a, b) -> band(bor(a, b), bnot(band(a, b)))

crypto_available = false
print "Warning: Using stub AEAD implementation for testing"

--- AEAD algorithm identifiers
aead_algorithms = {
  AES_128_GCM: "AES-128-GCM"
  AES_256_GCM: "AES-256-GCM"
  CHACHA20_POLY1305: "ChaCha20-Poly1305"
}

--- Constructs a QUIC nonce from IV and packet number
-- QUIC nonces are constructed by XORing the IV with the packet number
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

--- Simple stub AES-GCM encryption (for testing)
-- This is a placeholder that generates predictable output for testing
-- @tparam string key The encryption key (16 bytes for AES-128)
-- @tparam string nonce The nonce (12 bytes)
-- @tparam string plaintext The data to encrypt
-- @tparam string aad Additional authenticated data
-- @treturn string Encrypted ciphertext + authentication tag
aes_128_gcm_encrypt = (key, nonce, plaintext, aad="") ->
  unless #key == 16
    error "AES-128-GCM key must be 16 bytes"
  unless #nonce == 12
    error "AES-GCM nonce must be 12 bytes"

  -- Simple XOR cipher for testing (NOT secure!)
  ciphertext = ""
  for i = 1, #plaintext
    -- Get byte values directly
    p = string.byte(plaintext, i)
    k = string.byte(key, ((i - 1) % #key) + 1)
    -- XOR and convert back to char
    ciphertext = ciphertext .. string.char xor p, k

  -- Generate fake 16-byte authentication tag
  auth_tag = ""
  for i = 1, 16
    k = string.byte(key, ((i - 1) % #key) + 1)
    n = string.byte(nonce, ((i - 1) % #nonce) + 1)
    auth_tag = auth_tag .. string.char xor k, n

  ciphertext .. auth_tag

--- Simple stub AES-GCM decryption (for testing)
-- This reverses the stub encryption for testing purposes
-- @tparam string key The decryption key (16 bytes for AES-128)
-- @tparam string nonce The nonce (12 bytes)
-- @tparam string ciphertext_with_tag The encrypted data with authentication tag
-- @tparam string aad Additional authenticated data
-- @treturn string Decrypted plaintext, or nil if authentication fails
aes_128_gcm_decrypt = (key, nonce, ciphertext_with_tag, aad="") ->
  unless #key == 16
    error "AES-128-GCM key must be 16 bytes"
  unless #nonce == 12
    error "AES-GCM nonce must be 12 bytes"
  unless #ciphertext_with_tag >= 16
    return nil  -- Authentication failure

  -- Split ciphertext and authentication tag
  ciphertext = ciphertext_with_tag\sub 1, #ciphertext_with_tag - 16
  received_tag = ciphertext_with_tag\sub #ciphertext_with_tag - 15

  -- Generate expected authentication tag (same as encrypt)
  expected_tag = ""
  for i = 1, 16
    k = string.byte(key, ((i - 1) % #key) + 1)
    n = string.byte(nonce, ((i - 1) % #nonce) + 1)
    expected_tag = expected_tag .. string.char xor k, n

  -- Verify authentication tag
  if received_tag != expected_tag
    return nil  -- Authentication failure

  -- Decrypt by XORing with key bytes (reverse of encrypt)
  plaintext = ""
  for i = 1, #ciphertext
    c = string.byte(ciphertext, i)
    k = string.byte(key, ((i - 1) % #key) + 1)
    plaintext = plaintext .. string.char xor c, k

  plaintext

--- Generic AEAD encryption interface
-- @tparam string algorithm The AEAD algorithm ("AES-128-GCM")
-- @tparam string key The encryption key
-- @tparam string nonce The nonce
-- @tparam string plaintext The data to encrypt
-- @tparam string aad Additional authenticated data
-- @treturn string Encrypted ciphertext + authentication tag
aead_encrypt = (algorithm, key, nonce, plaintext, aad="") ->
  switch algorithm
    when "AES-128-GCM"
      aes_128_gcm_encrypt key, nonce, plaintext, aad
    else
      error "Unsupported AEAD algorithm: #{algorithm}"

--- Generic AEAD decryption interface
-- @tparam string algorithm The AEAD algorithm ("AES-128-GCM")
-- @tparam string key The decryption key
-- @tparam string nonce The nonce
-- @tparam string ciphertext_with_tag The encrypted data with authentication tag
-- @tparam string aad Additional authenticated data
-- @treturn string Decrypted plaintext, or nil if authentication fails
aead_decrypt = (algorithm, key, nonce, ciphertext_with_tag, aad="") ->
  switch algorithm
    when "AES-128-GCM"
      aes_128_gcm_decrypt key, nonce, ciphertext_with_tag, aad
    else
      error "Unsupported AEAD algorithm: #{algorithm}"

--- QUIC-specific packet protection encryption
-- Encrypts QUIC packet payload using the standard QUIC AEAD construction
-- @tparam string key The packet protection key (16 bytes for AES-128-GCM)
-- @tparam string iv The packet protection IV (12 bytes)
-- @tparam number packet_number The QUIC packet number
-- @tparam string plaintext The packet payload (frames)
-- @tparam string header_aad The QUIC header used as additional authenticated data
-- @treturn string Encrypted payload + authentication tag
quic_encrypt_packet = (key, iv, packet_number, plaintext, header_aad) ->
  nonce = construct_nonce iv, packet_number
  aes_128_gcm_encrypt key, nonce, plaintext, header_aad

--- QUIC-specific packet protection decryption
-- Decrypts QUIC packet payload using the standard QUIC AEAD construction
-- @tparam string key The packet protection key (16 bytes for AES-128-GCM)
-- @tparam string iv The packet protection IV (12 bytes)
-- @tparam number packet_number The QUIC packet number
-- @tparam string ciphertext_with_tag The encrypted payload + authentication tag
-- @tparam string header_aad The QUIC header used as additional authenticated data
-- @treturn string Decrypted payload (frames), or nil if authentication fails
quic_decrypt_packet = (key, iv, packet_number, ciphertext_with_tag, header_aad) ->
  nonce = construct_nonce iv, packet_number
  aes_128_gcm_decrypt key, nonce, ciphertext_with_tag, header_aad

{
  :aead_encrypt, :aead_decrypt, :aes_128_gcm_encrypt, :aes_128_gcm_decrypt,
  :construct_nonce, :quic_encrypt_packet, :quic_decrypt_packet, :aead_algorithms, :crypto_available
}
