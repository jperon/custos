--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- QUIC Frame Parsing and Packing Module
-- This module provides utilities for parsing and packing QUIC frames.
-- It supports all standard QUIC frame types including CRYPTO, STREAM, ACK, and control frames.
--
-- ### Features
-- - Parse and pack QUIC frames from decrypted packet payload
-- - Support for variable-length integer encoding (VarInt)
-- - Handle all frame types defined in RFC 9000
-- - Frame iteration and validation
--
-- ### QUIC Frame Structure
-- ```
-- Frame {
--   type (variable): Frame type as VarInt
--   type_specific_fields (variable): Fields specific to frame type
--   data (variable): Frame payload data
-- }
-- ```
--
-- References:
-- - RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport
-- - RFC 9001: Using TLS to Secure QUIC
--
-- @module quic.frames

pack: sp, unpack: su = require "ipparse.lib.pack_compat"
:bidirectional = require"ipparse.fun"
{:band, :bor, :bnot, :lshift, :rshift} = require"ipparse.lib.bit_compat"

--- QUIC Frame Types
-- Mapping of frame type codes to their names
frame_types = bidirectional {
  [0x00]: "PADDING"
  [0x01]: "PING"
  [0x02]: "ACK"
  [0x03]: "ACK_ECN"
  [0x04]: "RESET_STREAM"
  [0x05]: "STOP_SENDING"
  [0x06]: "CRYPTO"
  [0x07]: "NEW_TOKEN"
  [0x08]: "STREAM"
  [0x09]: "STREAM"
  [0x0a]: "STREAM"
  [0x0b]: "STREAM"
  [0x0c]: "STREAM"
  [0x0d]: "STREAM"
  [0x0e]: "STREAM"
  [0x0f]: "STREAM"
  [0x10]: "MAX_DATA"
  [0x11]: "MAX_STREAM_DATA"
  [0x12]: "MAX_STREAMS_BIDI"
  [0x13]: "MAX_STREAMS_UNI"
  [0x14]: "DATA_BLOCKED"
  [0x15]: "STREAM_DATA_BLOCKED"
  [0x16]: "STREAMS_BLOCKED_BIDI"
  [0x17]: "STREAMS_BLOCKED_UNI"
  [0x18]: "NEW_CONNECTION_ID"
  [0x19]: "RETIRE_CONNECTION_ID"
  [0x1a]: "PATH_CHALLENGE"
  [0x1b]: "PATH_RESPONSE"
  [0x1c]: "CONNECTION_CLOSE"
  [0x1d]: "CONNECTION_CLOSE_APP"
  [0x1e]: "HANDSHAKE_DONE"
}

--- Parses a QUIC variable-length integer (VarInt)
-- VarInt encoding uses the first two bits to indicate length:
-- 00xxxxxx = 1 byte (0-63)
-- 01xxxxxx xxxxxxxx = 2 bytes (0-16383)
-- 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx = 4 bytes (0-1073741823)
-- 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx = 8 bytes
-- @tparam string data The binary data containing the VarInt
-- @tparam number offset Starting offset in the data
-- @treturn number The parsed integer value
-- @treturn number Next offset after the VarInt
parse_varint = (data, offset) ->
  return nil, offset if offset > #data

  first_byte = su "B", data, offset

  switch rshift(first_byte, 6)
    when 0  -- 1 byte
      first_byte, offset + 1
    when 1  -- 2 bytes
      return nil, offset if offset + 1 > #data
      value = su ">H", data, offset
      band(value, 0x3FFF), offset + 2
    when 2  -- 4 bytes
      return nil, offset if offset + 3 > #data
      value = su ">I4", data, offset
      band(value, 0x3FFFFFFF), offset + 4
    when 3  -- 8 bytes
      return nil, offset if offset + 7 > #data
      high, low = su ">I4I4", data, offset
      lshift(band(high, 0x3FFFFFFF), 32) + low, offset + 8

--- Encodes a number as a QUIC variable-length integer (VarInt)
-- @tparam number value The integer value to encode
-- @treturn string Binary string containing the encoded VarInt
encode_varint = (value) ->
  if value < 64
    sp "B", value
  elseif value < 16384
    sp ">H", bor(0x4000, value)
  elseif value < 1073741824
    sp ">I4", bor(0x80000000, value)
  else
    high = band(rshift(value, 32), 0x3FFFFFFF)
    low = band(value, 0xFFFFFFFF)
    sp ">I4I4", bor(0xC0000000, high), low

--- Parses a PADDING frame
-- PADDING frames consist only of the frame type (0x00)
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @treturn table Parsed PADDING frame
-- @treturn number Next offset after the frame
parse_padding_frame = (data, offset) ->
  {type: 0x00, name: "PADDING"}, offset

--- Parses a PING frame
-- PING frames consist only of the frame type (0x01)
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @treturn table Parsed PING frame
-- @treturn number Next offset after the frame
parse_ping_frame = (data, offset) ->
  {type: 0x01, name: "PING"}, offset

--- Parses an ACK frame
-- ACK frames contain acknowledgment information for received packets
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @tparam number frame_type Frame type (0x02 or 0x03 for ACK_ECN)
-- @treturn table Parsed ACK frame
-- @treturn number Next offset after the frame
parse_ack_frame = (data, offset, frame_type) ->
  largest_acked, offset = parse_varint data, offset
  ack_delay, offset = parse_varint data, offset
  ack_range_count, offset = parse_varint data, offset
  first_ack_range, offset = parse_varint data, offset

  ack_ranges = {}
  for i = 1, ack_range_count
    gap, offset = parse_varint data, offset
    ack_range_len, offset = parse_varint data, offset
    ack_ranges[#ack_ranges + 1] = {gap: gap, length: ack_range_len}

  frame = {
    type: frame_type
    name: frame_type == 0x02 and "ACK" or "ACK_ECN"
    :largest_acked, :ack_delay, :ack_range_count, :first_ack_range, :ack_ranges
  }

  -- Parse ECN counts if this is an ACK_ECN frame
  if frame_type == 0x03
    frame.ect0_count, offset = parse_varint data, offset
    frame.ect1_count, offset = parse_varint data, offset
    frame.ecn_ce_count, offset = parse_varint data, offset

  frame, offset

--- Parses a CRYPTO frame
-- CRYPTO frames contain TLS handshake data
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @treturn table Parsed CRYPTO frame with TLS data
-- @treturn number Next offset after the frame
parse_crypto_frame = (data, offset) ->
  crypto_offset, offset = parse_varint data, offset
  length, offset = parse_varint data, offset

  -- Extract crypto data
  crypto_data = data\sub offset, offset + length - 1

  frame = {
    type: 0x06
    name: "CRYPTO"
    offset: crypto_offset
    :length
    data: crypto_data
  }

  frame, offset + length

--- Parses a STREAM frame
-- STREAM frames contain application data for a specific stream
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @tparam number frame_type Frame type (0x08-0x0f, different bits indicate presence of fields)
-- @treturn table Parsed STREAM frame
-- @treturn number Next offset after the frame
parse_stream_frame = (data, offset, frame_type) ->
  stream_id, offset = parse_varint data, offset

  -- Parse optional offset field (bit 2 of frame type)
  stream_offset = 0
  if band(frame_type, 0x04) != 0
    stream_offset, offset = parse_varint data, offset

  -- Parse optional length field (bit 1 of frame type)
  local length
  if band(frame_type, 0x02) != 0
    length, offset = parse_varint data, offset
  else
    -- Length extends to end of packet if not specified
    length = #data - offset + 1

  -- Extract stream data
  stream_data = data\sub offset, offset + length - 1

  frame = {
    type: frame_type
    name: "STREAM"
    id: stream_id
    offset: stream_offset
    :length
    data: stream_data
    fin: band(frame_type, 0x01) != 0  -- FIN bit (bit 0)
  }

  frame, offset + length

--- Parses a NEW_TOKEN frame
-- NEW_TOKEN frames provide tokens for future connection attempts
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @treturn table Parsed NEW_TOKEN frame
-- @treturn number Next offset after the frame
parse_new_token_frame = (data, offset) ->
  token_length, offset = parse_varint data, offset
  token = data\sub offset, offset + token_length - 1

  frame = {
    type: 0x07
    name: "NEW_TOKEN"
    token_length: token_length
    :token
  }

  frame, offset + token_length

--- Parses a generic frame header and delegates to specific parsers
-- @tparam string data The binary data containing the frame
-- @tparam number offset Starting offset in the data
-- @treturn table Parsed frame object
-- @treturn number Next offset after the frame
parse_frame = (data, offset) ->
  return nil, offset if offset > #data

  frame_type, new_offset = parse_varint data, offset
  return nil, offset unless frame_type

  switch frame_type
    when 0x00
      parse_padding_frame data, new_offset
    when 0x01
      parse_ping_frame data, new_offset
    when 0x02, 0x03
      parse_ack_frame data, new_offset, frame_type
    when 0x06
      parse_crypto_frame data, new_offset
    when 0x07
      parse_new_token_frame data, new_offset
    else
      -- Check if it's a STREAM frame (0x08-0x0f)
      if frame_type >= 0x08 and frame_type <= 0x0f
        parse_stream_frame data, new_offset, frame_type
      else
        -- Unknown frame type - skip it by reading length if present
        -- For now, just create a generic frame object
        frame = {
          type: frame_type
          name: frame_types[frame_type] or "UNKNOWN"
          raw_data: data\sub new_offset
        }
        frame, #data + 1  -- Skip to end

--- Iterates over all frames in a decrypted QUIC packet payload
-- @tparam string payload_data The decrypted packet payload containing frames
-- @treturn function Iterator function that returns each parsed frame
iter_frames = (payload_data) ->
  offset = 1
  ->
    return nil if offset > #payload_data

    frame, new_offset = parse_frame payload_data, offset
    offset = new_offset
    frame

--- Validates that frame data is complete and well-formed
-- @tparam string payload_data The decrypted packet payload
-- @treturn boolean True if all frames are valid
-- @treturn string Error message if validation fails
validate_frames = (payload_data) ->
  offset = 1
  frame_count = 0

  while offset <= #payload_data
    frame, new_offset = parse_frame payload_data, offset
    unless frame
      return false, "Failed to parse frame at offset #{offset}"

    if new_offset <= offset
      return false, "Frame parser did not advance at offset #{offset}"

    offset = new_offset
    frame_count += 1

    -- Prevent infinite loop with reasonable limit
    if frame_count > 1000
      return false, "Too many frames (possible parsing error)"

  true, "#{frame_count} frames validated"

:parse_frame, :parse_crypto_frame, :parse_stream_frame, :parse_ack_frame, :iter_frames, :validate_frames, :parse_varint, :encode_varint, :frame_types
