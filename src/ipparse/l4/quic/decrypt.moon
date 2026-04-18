--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC Packet Decryption Pipeline
-- This module integrates all QUIC cryptographic components to provide
-- a complete packet decryption pipeline for QUIC Initial packets.
--
-- ### Features
-- - Complete QUIC Initial packet decryption
-- - Header protection removal and packet number recovery
-- - AEAD payload decryption with authentication
-- - Frame parsing from decrypted payload
-- - Integration with existing crypto components
--
-- ### Usage
-- ```
-- -- Decrypt a complete QUIC Initial packet
-- decryptor = QuicDecryptor(connection_id)
-- frames = decryptor\decrypt_initial_packet(packet_data)
-- ```
--
-- References:
-- - RFC 9001: Using TLS to Secure QUIC
-- - RFC 9000: QUIC Transport Protocol
--
-- @module quic.decrypt

crypto = require "ipparse.l4.quic.crypto"
aead = require "ipparse.lib.crypto.aead"
frames = require "ipparse.l4.quic.frames"
quic = require "ipparse.l4.quic"
:bin2hex, :hex2bin = require "ipparse.init"
{:band, :bor, :bnot, :lshift, :rshift} = require "ipparse.lib.bit_compat"

pack: sp, unpack: su = require "ipparse.lib.pack_compat"

--- QUIC Decryptor Class
-- Handles decryption of QUIC packets for a specific connection
class QuicDecryptor

  --- Initialize decryptor for a QUIC connection
  -- @tparam string connection_id The destination connection ID from Initial packets
  new: (connection_id) =>
    @connection_id = connection_id
    @client_secret, @server_secret = crypto.derive_initial_secrets connection_id

    -- Derive client keys (for client->server traffic)
    @client_key, @client_iv, @client_hp_key = crypto.derive_packet_protection_keys @client_secret

    -- Derive server keys (for server->client traffic)
    @server_key, @server_iv, @server_hp_key = crypto.derive_packet_protection_keys @server_secret

    -- Track expected packet numbers for each direction
    @expected_client_pn = 0
    @expected_server_pn = 0

    print "QuicDecryptor initialized for connection #{bin2hex connection_id}"
    print "  Client key: #{bin2hex @client_key}"
    print "  Server key: #{bin2hex @server_key}"

  --- Determines if packet is from client or server based on content
  -- For Initial packets, we use heuristics since we may not have full context
  -- @tparam string packet_data Raw packet data
  -- @treturn boolean True if packet is from client to server
  is_client_packet: (packet_data) =>
    -- Simple heuristic: assume packets with certain patterns are client packets
    -- In practice, you'd use connection state or port analysis
    -- For now, assume all Initial packets we see are client packets
    true

  --- Extracts sample for header protection from packet payload
  -- Sample is taken from a fixed offset in the encrypted payload
  -- @tparam string packet_data Complete packet data
  -- @tparam number payload_offset Offset where encrypted payload starts
  -- @treturn string 16-byte sample for header protection
  extract_sample: (packet_data, payload_offset) =>
    -- QUIC spec: sample starts 4 bytes into the encrypted payload
    sample_offset = payload_offset + 4

    if sample_offset + 16 > #packet_data
      error "Packet too short to extract header protection sample"

    packet_data\sub sample_offset, sample_offset + 15

  --- Removes header protection and recovers packet number
  -- @tparam string packet_data Complete packet data
  -- @tparam boolean is_client True if this is a client packet
  -- @treturn string Unprotected header
  -- @treturn number Recovered packet number
  -- @treturn number Payload offset after unprotected header
  remove_header_protection: (packet_data, is_client=true) =>
    -- Parse basic QUIC header structure to find payload
    unless #packet_data >= 20  -- Minimum for long header
      error "Packet too short for QUIC Initial packet"

    -- Parse long header format
    first_byte = su "B", packet_data, 1
    unless band(first_byte, 0x80) != 0  -- Long header bit
      error "Expected long header packet"

    version = su ">I4", packet_data, 2
    dcid_len = su "B", packet_data, 6
    dcid = packet_data\sub 7, 6 + dcid_len
    scid_len = su "B", packet_data, 7 + dcid_len
    scid = packet_data\sub 8 + dcid_len, 7 + dcid_len + scid_len

    -- For Initial packets, there's a token length field
    token_len_offset = 8 + dcid_len + scid_len
    token_len, token_len_size = frames.parse_varint packet_data, token_len_offset
    token_offset = token_len_offset + token_len_size
    token = packet_data\sub token_offset, token_offset + token_len - 1

    -- Then there's the length field (VarInt)
    length_offset = token_offset + token_len
    payload_length, length_size = frames.parse_varint packet_data, length_offset

    -- Payload starts after length field
    payload_offset = length_offset + length_size

    -- Extract sample for header protection
    sample = @extract_sample packet_data, payload_offset

    -- Choose keys based on packet direction
    hp_key = is_client and @client_hp_key or @server_hp_key
    expected_pn = is_client and @expected_client_pn or @expected_server_pn

    -- Remove header protection
    unprotected_header, recovered_pn = crypto.recover_quic_packet_number(
      packet_data\sub(1, payload_offset - 1),
      hp_key,
      sample,
      expected_pn,
      true  -- Long header
    )

    -- Update expected packet number
    if is_client
      @expected_client_pn = recovered_pn + 1
    else
      @expected_server_pn = recovered_pn + 1

    unprotected_header, recovered_pn, payload_offset

  --- Decrypts QUIC packet payload using AEAD
  -- @tparam string packet_data Complete packet data
  -- @tparam string unprotected_header Header to use as AAD
  -- @tparam number packet_number Recovered packet number
  -- @tparam number payload_offset Start of encrypted payload
  -- @tparam boolean is_client True if this is a client packet
  -- @treturn string Decrypted payload containing frames
  decrypt_payload: (packet_data, unprotected_header, packet_number, payload_offset, is_client=true) =>
    -- Extract encrypted payload
    encrypted_payload = packet_data\sub payload_offset

    -- Choose keys based on packet direction
    key = is_client and @client_key or @server_key
    iv = is_client and @client_iv or @server_iv

    -- Decrypt using QUIC packet protection
    decrypted_payload = aead.quic_decrypt_packet(
      key,
      iv,
      packet_number,
      encrypted_payload,
      unprotected_header
    )

    unless decrypted_payload
      error "Failed to decrypt QUIC packet payload - authentication failed"

    decrypted_payload

  --- Decrypts a complete QUIC Initial packet
  -- @tparam string packet_data Raw packet data
  -- @treturn table Array of parsed frames from decrypted payload
  -- @treturn table Packet metadata (packet number, keys used, etc.)
  decrypt_initial_packet: (packet_data) =>
    print "Decrypting QUIC Initial packet (#{#packet_data} bytes)"

    -- Determine packet direction
    is_client = @is_client_packet packet_data
    direction = is_client and "client->server" or "server->client"
    print "  Direction: #{direction}"

    -- Step 1: Remove header protection and recover packet number
    unprotected_header, packet_number, payload_offset = @remove_header_protection packet_data, is_client
    print "  Recovered packet number: #{packet_number}"
    print "  Payload offset: #{payload_offset}"

    -- Step 2: Decrypt payload
    decrypted_payload = @decrypt_payload packet_data, unprotected_header, packet_number, payload_offset, is_client
    print "  Decrypted payload length: #{#decrypted_payload} bytes"

    -- Step 3: Parse frames from decrypted payload
    parsed_frames = {}
    for frame in frames.iter_frames decrypted_payload
      parsed_frames[#parsed_frames + 1] = frame
      print "  Found #{frame.name} frame"

    -- Step 4: Validate frames
    valid, msg = frames.validate_frames decrypted_payload
    unless valid
      print "  Warning: Frame validation failed: #{msg}"

    metadata = {
      :packet_number, :is_client, :direction,
      :payload_offset, :unprotected_header,
      decrypted_payload_length: #decrypted_payload,
      frame_count: #parsed_frames,
      keys_used: {
        key: bin2hex(is_client and @client_key or @server_key),
        iv: bin2hex(is_client and @client_iv or @server_iv),
        hp_key: bin2hex(is_client and @client_hp_key or @server_hp_key)
      }
    }

    parsed_frames, metadata

--- Convenience function to decrypt a single QUIC Initial packet
-- @tparam string connection_id Destination connection ID
-- @tparam string packet_data Raw packet data
-- @treturn table Array of parsed frames
-- @treturn table Packet metadata
decrypt_quic_initial = (connection_id, packet_data) ->
  decryptor = QuicDecryptor connection_id
  decryptor\decrypt_initial_packet packet_data

--- Decrypts multiple QUIC packets from the same connection
-- @tparam string connection_id Destination connection ID
-- @tparam table packets Array of raw packet data
-- @treturn table Array of {frames, metadata} for each successfully decrypted packet
decrypt_quic_packets = (connection_id, packets) ->
  decryptor = QuicDecryptor connection_id
  results = {}

  for i, packet_data in ipairs packets
    print "\n=== Decrypting packet #{i} ==="

    success, frames_or_error, metadata = pcall ->
      decryptor\decrypt_initial_packet packet_data

    if success
      results[#results + 1] = {
        packet_index: i,
        frames: frames_or_error,
        :metadata,
        success: true
      }
      print "✓ Packet #{i} decrypted successfully (#{#frames_or_error} frames)"
    else
      results[#results + 1] = {
        packet_index: i,
        error: frames_or_error,
        success: false
      }
      print "✗ Packet #{i} decryption failed: #{frames_or_error}"

  results

{
  :QuicDecryptor, :decrypt_quic_initial, :decrypt_quic_packets
}
