--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC Cryptography Module
-- This module provides cryptographic utilities for QUIC packet protection,
-- including header protection and packet number recovery.
--
-- ### Features
-- - Header protection removal using AES-ECB
-- - Packet number recovery from protected headers
-- - Key derivation for QUIC Initial packets
-- - Support for QUIC v1 cryptographic operations
--
-- ### QUIC Header Protection
-- ```
-- -- Remove header protection to recover packet number
-- hp_key = derive_header_protection_key(...)
-- unprotected_header = remove_header_protection(protected_header, hp_key, sample)
-- packet_number = extract_packet_number(unprotected_header)
-- ```
--
-- References:
-- - RFC 9001: Using TLS to Secure QUIC (Section 5.4)
-- - RFC 9000: QUIC Transport Protocol
--
-- @module quic.crypto

pack: sp, unpack: su = require "ipparse.lib.pack_compat"
hkdf = require "ipparse.lib.hkdf"
aead = require "ipparse.lib.crypto.aead"
:bin2hex, :hex2bin = require "ipparse.init"
{:band, :bor, :bnot, :lshift, :rshift} = require "ipparse.lib.bit_compat"

-- Use the same XOR workaround as AEAD module
xor = (a, b) -> band(bor(a, b), bnot(band(a, b)))

--- QUIC v1 Initial Salt (from RFC 9001)
-- This is the standard salt used for QUIC v1 Initial packet key derivation
QUIC_V1_INITIAL_SALT = hex2bin "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"

--- QUIC Label prefixes for key derivation
QUIC_LABELS = {
  CLIENT_INITIAL: "client in"
  SERVER_INITIAL: "server in"
  HEADER_PROTECTION: "quic hp"
  PACKET_PROTECTION_KEY: "quic key"
  PACKET_PROTECTION_IV: "quic iv"
}

--- Derives QUIC Initial secrets from connection ID
-- Uses HKDF-Extract with the QUIC v1 salt and connection ID
-- @tparam string connection_id The destination connection ID from Initial packet
-- @treturn string client_initial_secret (32 bytes)
-- @treturn string server_initial_secret (32 bytes)
derive_initial_secrets = (connection_id) ->
  -- HKDF-Extract(salt=QUIC_V1_INITIAL_SALT, ikm=connection_id)
  initial_secret = hkdf.hkdf_extract QUIC_V1_INITIAL_SALT, connection_id

  -- Derive client and server initial secrets (convert hex to binary)
  client_secret = hex2bin hkdf.hkdf_expand_label initial_secret, QUIC_LABELS.CLIENT_INITIAL, "", 32
  server_secret = hex2bin hkdf.hkdf_expand_label initial_secret, QUIC_LABELS.SERVER_INITIAL, "", 32

  client_secret, server_secret

--- Derives packet protection keys and IVs from initial secret
-- @tparam string initial_secret The initial secret (32 bytes)
-- @treturn string packet_key (16 bytes for AES-128-GCM)
-- @treturn string packet_iv (12 bytes)
-- @treturn string header_protection_key (16 bytes)
derive_packet_protection_keys = (initial_secret) ->
  -- Convert hex strings to binary
  packet_key = hex2bin hkdf.hkdf_expand_label initial_secret, QUIC_LABELS.PACKET_PROTECTION_KEY, "", 16
  packet_iv = hex2bin hkdf.hkdf_expand_label initial_secret, QUIC_LABELS.PACKET_PROTECTION_IV, "", 12
  hp_key = hex2bin hkdf.hkdf_expand_label initial_secret, QUIC_LABELS.HEADER_PROTECTION, "", 16

  packet_key, packet_iv, hp_key

--- Stub AES-ECB encryption (for header protection)
-- This is a simplified version for testing without real crypto library
-- @tparam string key AES key (16 bytes)
-- @tparam string plaintext Input data (16 bytes)
-- @treturn string Encrypted data (16 bytes)
stub_aes_ecb_encrypt = (key, plaintext) ->
  unless #key == 16
    error "AES key must be 16 bytes"
  unless #plaintext == 16
    error "AES-ECB input must be 16 bytes"

  -- Simple XOR cipher for testing (NOT secure!)
  ciphertext = ""
  for i = 1, 16
    p = string.byte(plaintext, i)
    k = string.byte(key, ((i - 1) % #key) + 1)
    ciphertext = ciphertext .. string.char(xor p, k)

  ciphertext

--- Generates header protection mask
-- Uses AES-ECB to generate a mask from the packet sample
-- @tparam string hp_key Header protection key (16 bytes)
-- @tparam string sample Packet sample (16 bytes from payload)
-- @treturn string Header protection mask (5 bytes for long header, 1 byte for short)
generate_header_mask = (hp_key, sample) ->
  unless #hp_key == 16
    error "Header protection key must be 16 bytes"
  unless #sample == 16
    error "Sample must be 16 bytes"

  -- Generate mask using AES-ECB
  mask_block = stub_aes_ecb_encrypt hp_key, sample

  -- Return first 5 bytes as mask (sufficient for long and short headers)
  mask_block\sub 1, 5

--- Removes header protection from QUIC packet
-- Recovers the true packet number and first byte from protected header
-- @tparam string protected_header The protected QUIC header
-- @tparam string hp_key Header protection key (16 bytes)
-- @tparam string sample Sample from packet payload (16 bytes)
-- @tparam boolean is_long_header True if this is a long header packet
-- @treturn string Unprotected header with recovered packet number
-- @treturn number Recovered packet number
remove_header_protection = (protected_header, hp_key, sample, is_long_header=true) ->
  unless #protected_header >= (is_long_header and 4 or 1)
    error "Header too short for protection removal"

  -- Generate header protection mask
  mask = generate_header_mask hp_key, sample

  -- Create mutable copy of header
  unprotected = ""
  for i = 1, #protected_header
    unprotected ..= string.char(string.byte(protected_header, i))

  if is_long_header
    -- Long header: protect first byte and up to 4 bytes of packet number
    first_byte = string.byte(protected_header, 1)
    mask_first = string.byte(mask, 1)

    -- Remove protection from first byte (only lower 4 bits are protected)
    unprotected_first = xor(first_byte, band(mask_first, 0x0F))
    unprotected = string.char(unprotected_first) .. unprotected\sub(2)

    -- Determine packet number length from first byte
    pn_length = band(unprotected_first, 0x03) + 1

    -- Remove protection from packet number bytes
    -- For long headers, packet number starts after fixed header
    -- We'll assume it starts at a known offset for simplicity
    pn_offset = is_long_header and (#protected_header - pn_length + 1) or 2

    for i = 1, pn_length
      if pn_offset + i - 1 <= #protected_header
        protected_byte = string.byte(protected_header, pn_offset + i - 1)
        mask_byte = string.byte(mask, i + 1)  -- Skip first mask byte used for first byte
        unprotected_byte = xor(protected_byte, mask_byte)

        -- Replace byte in unprotected header
        before = unprotected\sub(1, pn_offset + i - 2)
        after = unprotected\sub(pn_offset + i)
        unprotected = before .. string.char(unprotected_byte) .. after

    -- Extract packet number
    packet_number = 0
    for i = 1, pn_length
      if pn_offset + i - 1 <= #unprotected
        byte_val = string.byte(unprotected, pn_offset + i - 1)
        packet_number = bor(lshift(packet_number, 8), byte_val)

    unprotected, packet_number

  else
    -- Short header: simpler protection scheme
    first_byte = string.byte(protected_header, 1)
    mask_first = string.byte(mask, 1)

    -- Remove protection from first byte (only lower 5 bits are protected)
    unprotected_first = xor(first_byte, band(mask_first, 0x1F))
    unprotected = string.char(unprotected_first) .. unprotected\sub(2)

    -- For short headers, assume single byte packet number for simplicity
    pn_length = band(unprotected_first, 0x03) + 1
    packet_number = 0

    for i = 1, pn_length
      if 1 + i <= #protected_header
        protected_byte = string.byte(protected_header, 1 + i)
        mask_byte = string.byte(mask, i + 1)
        unprotected_byte = xor(protected_byte, mask_byte)

        before = unprotected\sub(1, i)
        after = unprotected\sub(i + 2)
        unprotected = before .. string.char(unprotected_byte) .. after

        packet_number = bor(lshift(packet_number, 8), unprotected_byte)

    unprotected, packet_number

--- Recovers full packet number from truncated packet number
-- QUIC truncates packet numbers to save space, this recovers the full value
-- @tparam number truncated_pn The truncated packet number from header
-- @tparam number expected_pn The expected next packet number
-- @tparam number pn_nbits Number of bits in truncated packet number
-- @treturn number The recovered full packet number
recover_packet_number = (truncated_pn, expected_pn, pn_nbits) ->
  pn_win = lshift(1, pn_nbits)
  pn_hwin = pn_win // 2
  pn_mask = pn_win - 1

  -- The incoming packet number should be greater than expected_pn - pn_hwin
  -- and less than or equal to expected_pn + pn_hwin
  candidate_pn = bor(band(expected_pn, bnot(pn_mask)), truncated_pn)

  if candidate_pn <= expected_pn - pn_hwin
    candidate_pn + pn_win
  elseif candidate_pn > expected_pn + pn_hwin
    candidate_pn - pn_win
  else
    candidate_pn

--- Complete QUIC packet number recovery process
-- Combines header protection removal and packet number recovery
-- @tparam string protected_header Protected QUIC header
-- @tparam string hp_key Header protection key
-- @tparam string sample Sample from packet payload
-- @tparam number expected_pn Expected next packet number
-- @tparam boolean is_long_header True for long header packets
-- @treturn string Unprotected header
-- @treturn number Recovered full packet number
recover_quic_packet_number = (protected_header, hp_key, sample, expected_pn, is_long_header=true) ->
  -- Remove header protection
  unprotected_header, truncated_pn = remove_header_protection protected_header, hp_key, sample, is_long_header

  -- Determine number of bits in packet number (simplified)
  pn_nbits = 8  -- Assume 1 byte packet number for simplicity

  -- Recover full packet number
  full_pn = recover_packet_number truncated_pn, expected_pn, pn_nbits

  unprotected_header, full_pn

{
  :derive_initial_secrets, :derive_packet_protection_keys, :generate_header_mask,
  :remove_header_protection, :recover_packet_number, :recover_quic_packet_number,
  :QUIC_V1_INITIAL_SALT, :QUIC_LABELS
}
