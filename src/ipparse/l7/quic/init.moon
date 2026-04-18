--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC Layer 7 Module
-- This module provides Layer 7 (application layer) parsing for QUIC,
-- combining QUIC frame parsing with existing TLS parsers to extract
-- application-level information like SNI from QUIC CRYPTO frames.
--
-- ### Features
-- - CRYPTO frame TLS data extraction
-- - Integration with existing TLS parsers
-- - SNI extraction from QUIC handshakes
-- - Support for fragmented TLS messages across frames
-- - Connection state management for multi-packet handshakes
--
-- ### Usage
-- ```
-- -- Extract SNI from QUIC CRYPTO frames
-- quic_l7 = QuicL7Parser()
-- sni = quic_l7\extract_sni_from_frames(crypto_frames)
-- ```
--
-- References:
-- - RFC 9000: QUIC Transport Protocol
-- - RFC 9001: Using TLS to Secure QUIC
-- - RFC 8446: TLS 1.3
--
-- @module l7.quic

decrypt = require "ipparse.l4.quic.decrypt"
frames = require "ipparse.l4.quic.frames"
:bin2hex, :hex2bin = require "ipparse.init"

unpack: su = string

--- QUIC Layer 7 Parser Class
-- Handles extraction of application-layer data from QUIC connections
class QuicL7Parser

  --- Initialize the L7 parser
  new: =>
    -- Track TLS handshake state across multiple packets
    @tls_buffer = ""  -- Buffer for reassembling fragmented TLS messages
    @handshake_complete = false
    @sni_extracted = nil

    print "QuicL7Parser initialized"

  --- Extracts TLS data from CRYPTO frames
  -- CRYPTO frames contain TLS handshake messages that may be fragmented
  -- across multiple frames and packets
  -- @tparam table crypto_frames Array of CRYPTO frames from decrypted packets
  -- @treturn string Combined TLS handshake data
  extract_tls_data: (crypto_frames) =>
    -- Sort frames by offset to handle out-of-order delivery
    table.sort crypto_frames, (a, b) -> a.offset < b.offset

    tls_data = ""
    expected_offset = 0

    for frame in *crypto_frames
      if frame.name == "CRYPTO" and frame.data
        if frame.offset == expected_offset
          -- Frame is in sequence
          tls_data ..= frame.data
          expected_offset += #frame.data
          print "  Added CRYPTO frame: offset #{frame.offset}, length #{#frame.data}"
        elseif frame.offset > expected_offset
          -- Gap in data - may need buffering for out-of-order frames
          print "  Gap detected: expected offset #{expected_offset}, got #{frame.offset}"
          -- For now, we'll try to continue (real implementation would buffer)
          tls_data ..= frame.data
          expected_offset = frame.offset + #frame.data
        else
          -- Overlapping or duplicate data
          print "  Overlapping CRYPTO frame ignored: offset #{frame.offset}"

    print "Combined TLS data length: #{#tls_data} bytes"
    tls_data

  --- Parses TLS handshake messages from CRYPTO frame data
  -- @tparam string tls_data Combined TLS data from CRYPTO frames
  -- @treturn table Array of parsed TLS handshake messages
  parse_tls_handshake: (tls_data) =>
    return {} if #tls_data == 0

    handshake_messages = {}
    offset = 1

    while offset <= #tls_data
      -- Check if we have enough data for TLS record header
      break if offset + 5 > #tls_data

      -- Parse TLS record header
      content_type = su "B", tls_data, offset
      version = su ">H", tls_data, offset + 1
      length = su ">H", tls_data, offset + 3

      print "  TLS Record: type=#{content_type}, version=0x#{string.format "%04x", version}, length=#{length}"

      -- Check if we have the complete record
      if offset + 4 + length > #tls_data
        print "  Incomplete TLS record, stopping (offset=#{offset}, length=#{length}, total_data=#{#tls_data})"
        break

      -- Extract record data
      record_data = tls_data\sub offset + 5, offset + 4 + length

      -- Parse handshake messages if this is a handshake record
      if content_type == 0x16  -- TLS Handshake
        @parse_handshake_messages record_data, handshake_messages

      offset += 5 + length

    print "Parsed #{#handshake_messages} TLS handshake messages"
    handshake_messages

  --- Parses individual handshake messages from TLS record data
  -- @tparam string record_data TLS handshake record payload
  -- @tparam table messages Array to append parsed messages to
  parse_handshake_messages: (record_data, messages) =>
    offset = 1

    while offset <= #record_data
      -- Check for handshake message header
      break if offset + 4 > #record_data

      msg_type = su "B", record_data, offset
      msg_length = su ">I4", "\0" .. record_data\sub(offset + 1, offset + 3)  -- 24-bit length

      print "    Handshake message: type=#{msg_type}, length=#{msg_length}"

      -- Check if we have the complete message
      if offset + 4 + msg_length > #record_data
        print "    Incomplete handshake message, stopping (offset=#{offset}, msg_length=#{msg_length}, record_data=#{#record_data})"
        break

      -- Extract message data
      msg_data = record_data\sub offset + 4, offset + 3 + msg_length

      message = {
        type: msg_type,
        length: msg_length,
        data: msg_data,
        name: @get_handshake_message_name msg_type
      }

      messages[#messages + 1] = message
      print "    → #{message.name}"

      offset += 4 + msg_length

  --- Gets human-readable name for handshake message type
  -- @tparam number msg_type TLS handshake message type
  -- @treturn string Message type name
  get_handshake_message_name: (msg_type) =>
    message_names = {
      [1]: "ClientHello",
      [2]: "ServerHello",
      [4]: "NewSessionTicket",
      [8]: "EncryptedExtensions",
      [11]: "Certificate",
      [13]: "CertificateRequest",
      [15]: "CertificateVerify",
      [20]: "Finished"
    }

    message_names[msg_type] or "Unknown(#{msg_type})"

  --- Extracts SNI from TLS ClientHello message
  -- @tparam table client_hello Parsed ClientHello message
  -- @treturn string SNI hostname or nil if not found
  extract_sni_from_client_hello: (client_hello) =>
    return nil unless client_hello.type == 1  -- ClientHello

    data = client_hello.data
    return nil if #data < 38  -- Minimum ClientHello size

    offset = 1

    -- Skip version (2 bytes) and random (32 bytes)
    offset += 34

    -- Skip session ID
    return nil if offset > #data
    session_id_len = su "B", data, offset
    offset += 1 + session_id_len

    -- Skip cipher suites
    return nil if offset + 1 > #data
    cipher_suites_len = su ">H", data, offset
    offset += 2 + cipher_suites_len

    -- Skip compression methods
    return nil if offset > #data
    compression_len = su "B", data, offset
    offset += 1 + compression_len

    -- Parse extensions
    return nil if offset + 1 > #data
    extensions_len = su ">H", data, offset
    offset += 2

    extensions_end = offset + extensions_len - 1

    while offset < extensions_end
      return nil if offset + 3 > #data

      ext_type = su ">H", data, offset
      ext_len = su ">H", data, offset + 2
      offset += 4

      if ext_type == 0  -- Server Name Indication
        return @parse_sni_extension data\sub(offset, offset + ext_len - 1)

      offset += ext_len

    nil

  --- Parses SNI extension data
  -- @tparam string ext_data SNI extension payload
  -- @treturn string SNI hostname or nil
  parse_sni_extension: (ext_data) =>
    return nil if #ext_data < 5

    -- Debug the extension data
    print "    Parsing SNI extension data (#{#ext_data} bytes): #{bin2hex ext_data}"

    offset = 1
    list_len = su ">H", ext_data, offset
    offset += 2
    print "    Server name list length: #{list_len}"

    return nil if offset > #ext_data
    name_type = su "B", ext_data, offset
    offset += 1
    print "    Name type: #{name_type} (should be 0 for hostname)"

    return nil unless name_type == 0  -- hostname
    return nil if offset + 1 > #ext_data

    name_len = su ">H", ext_data, offset
    offset += 2
    print "    Hostname length: #{name_len}"

    -- Fixed bounds check
    return nil if offset + name_len > #ext_data + 1

    hostname = ext_data\sub offset, offset + name_len - 1
    print "    Found SNI: #{hostname}"
    hostname

  --- Processes decrypted QUIC frames to extract SNI
  -- @tparam table frames Array of parsed QUIC frames
  -- @treturn string SNI hostname or nil
  process_frames: (frames_array) =>
    -- Extract CRYPTO frames
    crypto_frames = {}
    for frame in *frames_array
      if frame.name == "CRYPTO"
        crypto_frames[#crypto_frames + 1] = frame

    return nil if #crypto_frames == 0

    print "Processing #{#crypto_frames} CRYPTO frames"

    -- Extract and parse TLS data
    tls_data = @extract_tls_data crypto_frames
    handshake_messages = @parse_tls_handshake tls_data

    -- Look for ClientHello and extract SNI
    for message in *handshake_messages
      if message.name == "ClientHello"
        sni = @extract_sni_from_client_hello message
        if sni
          @sni_extracted = sni
          return sni

    nil

--- Convenience function to extract SNI from QUIC connection
-- @tparam string connection_id QUIC connection ID
-- @tparam table packets Array of raw QUIC packet data
-- @treturn string SNI hostname or nil
extract_quic_sni = (connection_id, packets) ->
  -- Decrypt packets
  decryption_results = decrypt.decrypt_quic_packets connection_id, packets

  -- Collect all frames from successful decryptions
  all_frames = {}
  for result in *decryption_results
    if result.success
      for frame in *result.frames
        all_frames[#all_frames + 1] = frame

  -- Parse L7 data
  l7_parser = QuicL7Parser()
  l7_parser\process_frames all_frames

{
  :QuicL7Parser, :extract_quic_sni
}
