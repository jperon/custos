local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local bidirectional
bidirectional = require("ipparse.fun").bidirectional
local band, bor, bnot, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, lshift, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.lshift, _obj_0.rshift
end
local frame_types = bidirectional({
  [0x00] = "PADDING",
  [0x01] = "PING",
  [0x02] = "ACK",
  [0x03] = "ACK_ECN",
  [0x04] = "RESET_STREAM",
  [0x05] = "STOP_SENDING",
  [0x06] = "CRYPTO",
  [0x07] = "NEW_TOKEN",
  [0x08] = "STREAM",
  [0x09] = "STREAM",
  [0x0a] = "STREAM",
  [0x0b] = "STREAM",
  [0x0c] = "STREAM",
  [0x0d] = "STREAM",
  [0x0e] = "STREAM",
  [0x0f] = "STREAM",
  [0x10] = "MAX_DATA",
  [0x11] = "MAX_STREAM_DATA",
  [0x12] = "MAX_STREAMS_BIDI",
  [0x13] = "MAX_STREAMS_UNI",
  [0x14] = "DATA_BLOCKED",
  [0x15] = "STREAM_DATA_BLOCKED",
  [0x16] = "STREAMS_BLOCKED_BIDI",
  [0x17] = "STREAMS_BLOCKED_UNI",
  [0x18] = "NEW_CONNECTION_ID",
  [0x19] = "RETIRE_CONNECTION_ID",
  [0x1a] = "PATH_CHALLENGE",
  [0x1b] = "PATH_RESPONSE",
  [0x1c] = "CONNECTION_CLOSE",
  [0x1d] = "CONNECTION_CLOSE_APP",
  [0x1e] = "HANDSHAKE_DONE"
})
local parse_varint
parse_varint = function(data, offset)
  if offset > #data then
    return nil, offset
  end
  local first_byte = su("B", data, offset)
  local _exp_0 = rshift(first_byte, 6)
  if 0 == _exp_0 then
    return first_byte, offset + 1
  elseif 1 == _exp_0 then
    if offset + 1 > #data then
      return nil, offset
    end
    local value = su(">H", data, offset)
    return band(value, 0x3FFF), offset + 2
  elseif 2 == _exp_0 then
    if offset + 3 > #data then
      return nil, offset
    end
    local value = su(">I4", data, offset)
    return band(value, 0x3FFFFFFF), offset + 4
  elseif 3 == _exp_0 then
    if offset + 7 > #data then
      return nil, offset
    end
    local high, low = su(">I4I4", data, offset)
    return (band(high, 0x3FFFFFFF) * 4294967296) + low, offset + 8
  end
end
local need_bytes
need_bytes = function(data, offset, len)
  if offset < 1 or len < 0 then
    return false
  end
  return (offset + len - 1) <= #data
end
local parse_varint_required
parse_varint_required = function(data, offset, field_name)
  local value, next_off = parse_varint(data, offset)
  if value == nil then
    return nil, offset, "truncated " .. tostring(field_name)
  end
  return value, next_off
end
local encode_varint
encode_varint = function(value)
  if value < 64 then
    return sp("B", value)
  elseif value < 16384 then
    return sp(">H", bor(0x4000, value))
  elseif value < 1073741824 then
    return string.char(bor(0x80, band(rshift(value, 24), 0x3F)), band(rshift(value, 16), 0xFF), band(rshift(value, 8), 0xFF), band(value, 0xFF))
  else
    local high = math.floor(value / 4294967296)
    local low = value % 4294967296
    return string.char(bor(0xC0, band(math.floor(high / 16777216), 0x3F)), band(math.floor(high / 65536), 0xFF), band(math.floor(high / 256), 0xFF), band(high, 0xFF), band(math.floor(low / 16777216), 0xFF), band(math.floor(low / 65536), 0xFF), band(math.floor(low / 256), 0xFF), band(low, 0xFF))
  end
end
local parse_padding_frame
parse_padding_frame = function(data, offset)
  return {
    type = 0x00,
    name = "PADDING"
  }, offset
end
local parse_ping_frame
parse_ping_frame = function(data, offset)
  return {
    type = 0x01,
    name = "PING"
  }, offset
end
local parse_ack_frame
parse_ack_frame = function(data, offset, frame_type)
  local largest_acked, err
  largest_acked, offset, err = parse_varint_required(data, offset, "ACK largest_acked")
  if not (largest_acked ~= nil) then
    return nil, offset, err
  end
  local ack_delay
  ack_delay, offset, err = parse_varint_required(data, offset, "ACK ack_delay")
  if not (ack_delay ~= nil) then
    return nil, offset, err
  end
  local ack_range_count
  ack_range_count, offset, err = parse_varint_required(data, offset, "ACK ack_range_count")
  if not (ack_range_count ~= nil) then
    return nil, offset, err
  end
  local first_ack_range
  first_ack_range, offset, err = parse_varint_required(data, offset, "ACK first_ack_range")
  if not (first_ack_range ~= nil) then
    return nil, offset, err
  end
  local ack_ranges = { }
  for i = 1, ack_range_count do
    local gap
    gap, offset, err = parse_varint_required(data, offset, "ACK gap[" .. tostring(i) .. "]")
    if not (gap ~= nil) then
      return nil, offset, err
    end
    local ack_range_len
    ack_range_len, offset, err = parse_varint_required(data, offset, "ACK range_length[" .. tostring(i) .. "]")
    if not (ack_range_len ~= nil) then
      return nil, offset, err
    end
    ack_ranges[#ack_ranges + 1] = {
      gap = gap,
      length = ack_range_len
    }
  end
  local frame = {
    type = frame_type,
    name = frame_type == 0x02 and "ACK" or "ACK_ECN",
    largest_acked = largest_acked,
    ack_delay = ack_delay,
    ack_range_count = ack_range_count,
    first_ack_range = first_ack_range,
    ack_ranges = ack_ranges
  }
  if frame_type == 0x03 then
    frame.ect0_count, offset, err = parse_varint_required(data, offset, "ACK_ECN ect0_count")
    if not (frame.ect0_count ~= nil) then
      return nil, offset, err
    end
    frame.ect1_count, offset, err = parse_varint_required(data, offset, "ACK_ECN ect1_count")
    if not (frame.ect1_count ~= nil) then
      return nil, offset, err
    end
    frame.ecn_ce_count, offset, err = parse_varint_required(data, offset, "ACK_ECN ecn_ce_count")
    if not (frame.ecn_ce_count ~= nil) then
      return nil, offset, err
    end
  end
  return frame, offset
end
local parse_crypto_frame
parse_crypto_frame = function(data, offset)
  local crypto_offset, err
  crypto_offset, offset, err = parse_varint_required(data, offset, "CRYPTO offset")
  if not (crypto_offset ~= nil) then
    return nil, offset, err
  end
  local length
  length, offset, err = parse_varint_required(data, offset, "CRYPTO length")
  if not (length ~= nil) then
    return nil, offset, err
  end
  if not (need_bytes(data, offset, length)) then
    return nil, offset, "CRYPTO payload exceeds frame data"
  end
  local crypto_data = data:sub(offset, offset + length - 1)
  local frame = {
    type = 0x06,
    name = "CRYPTO",
    offset = crypto_offset,
    length = length,
    data = crypto_data
  }
  return frame, offset + length
end
local parse_stream_frame
parse_stream_frame = function(data, offset, frame_type)
  local stream_id, err
  stream_id, offset, err = parse_varint_required(data, offset, "STREAM id")
  if not (stream_id ~= nil) then
    return nil, offset, err
  end
  local stream_offset = 0
  if band(frame_type, 0x04) ~= 0 then
    stream_offset, offset, err = parse_varint_required(data, offset, "STREAM offset")
    if not (stream_offset ~= nil) then
      return nil, offset, err
    end
  end
  local length
  if band(frame_type, 0x02) ~= 0 then
    length, offset, err = parse_varint_required(data, offset, "STREAM length")
    if not (length ~= nil) then
      return nil, offset, err
    end
  else
    length = #data - offset + 1
  end
  if not (need_bytes(data, offset, length)) then
    return nil, offset, "STREAM payload exceeds frame data"
  end
  local stream_data = data:sub(offset, offset + length - 1)
  local frame = {
    type = frame_type,
    name = "STREAM",
    id = stream_id,
    offset = stream_offset,
    length = length,
    data = stream_data,
    fin = band(frame_type, 0x01) ~= 0
  }
  return frame, offset + length
end
local parse_new_token_frame
parse_new_token_frame = function(data, offset)
  local token_length, err
  token_length, offset, err = parse_varint_required(data, offset, "NEW_TOKEN length")
  if not (token_length ~= nil) then
    return nil, offset, err
  end
  if not (need_bytes(data, offset, token_length)) then
    return nil, offset, "NEW_TOKEN payload exceeds frame data"
  end
  local token = data:sub(offset, offset + token_length - 1)
  local frame = {
    type = 0x07,
    name = "NEW_TOKEN",
    token_length = token_length,
    token = token
  }
  return frame, offset + token_length
end
local parse_reset_stream_frame
parse_reset_stream_frame = function(data, offset)
  local stream_id, err
  stream_id, offset, err = parse_varint_required(data, offset, "RESET_STREAM id")
  if not (stream_id ~= nil) then
    return nil, offset, err
  end
  local app_error_code
  app_error_code, offset, err = parse_varint_required(data, offset, "RESET_STREAM app_error_code")
  if not (app_error_code ~= nil) then
    return nil, offset, err
  end
  local final_size
  final_size, offset, err = parse_varint_required(data, offset, "RESET_STREAM final_size")
  if not (final_size ~= nil) then
    return nil, offset, err
  end
  return {
    type = 0x04,
    name = "RESET_STREAM",
    stream_id = stream_id,
    app_error_code = app_error_code,
    final_size = final_size
  }, offset
end
local parse_stop_sending_frame
parse_stop_sending_frame = function(data, offset)
  local stream_id, err
  stream_id, offset, err = parse_varint_required(data, offset, "STOP_SENDING id")
  if not (stream_id ~= nil) then
    return nil, offset, err
  end
  local app_error_code
  app_error_code, offset, err = parse_varint_required(data, offset, "STOP_SENDING app_error_code")
  if not (app_error_code ~= nil) then
    return nil, offset, err
  end
  return {
    type = 0x05,
    name = "STOP_SENDING",
    stream_id = stream_id,
    app_error_code = app_error_code
  }, offset
end
local parse_max_data_frame
parse_max_data_frame = function(data, offset)
  local maximum_data, err
  maximum_data, offset, err = parse_varint_required(data, offset, "MAX_DATA maximum_data")
  if not (maximum_data ~= nil) then
    return nil, offset, err
  end
  return {
    type = 0x10,
    name = "MAX_DATA",
    maximum_data = maximum_data
  }, offset
end
local parse_max_stream_data_frame
parse_max_stream_data_frame = function(data, offset)
  local stream_id, err
  stream_id, offset, err = parse_varint_required(data, offset, "MAX_STREAM_DATA stream_id")
  if not (stream_id ~= nil) then
    return nil, offset, err
  end
  local maximum_stream_data
  maximum_stream_data, offset, err = parse_varint_required(data, offset, "MAX_STREAM_DATA maximum_stream_data")
  if not (maximum_stream_data ~= nil) then
    return nil, offset, err
  end
  return {
    type = 0x11,
    name = "MAX_STREAM_DATA",
    stream_id = stream_id,
    maximum_stream_data = maximum_stream_data
  }, offset
end
local parse_max_streams_frame
parse_max_streams_frame = function(data, offset, frame_type)
  local maximum_streams, err
  maximum_streams, offset, err = parse_varint_required(data, offset, "MAX_STREAMS maximum_streams")
  if not (maximum_streams ~= nil) then
    return nil, offset, err
  end
  local name = frame_type == 0x12 and "MAX_STREAMS_BIDI" or "MAX_STREAMS_UNI"
  return {
    type = frame_type,
    name = name,
    maximum_streams = maximum_streams
  }, offset
end
local parse_data_blocked_frame
parse_data_blocked_frame = function(data, offset)
  local maximum_data, err
  maximum_data, offset, err = parse_varint_required(data, offset, "DATA_BLOCKED maximum_data")
  if not (maximum_data ~= nil) then
    return nil, offset, err
  end
  return {
    type = 0x14,
    name = "DATA_BLOCKED",
    maximum_data = maximum_data
  }, offset
end
local parse_stream_data_blocked_frame
parse_stream_data_blocked_frame = function(data, offset)
  local stream_id, err
  stream_id, offset, err = parse_varint_required(data, offset, "STREAM_DATA_BLOCKED stream_id")
  if not (stream_id ~= nil) then
    return nil, offset, err
  end
  local maximum_stream_data
  maximum_stream_data, offset, err = parse_varint_required(data, offset, "STREAM_DATA_BLOCKED maximum_stream_data")
  if not (maximum_stream_data ~= nil) then
    return nil, offset, err
  end
  return {
    type = 0x15,
    name = "STREAM_DATA_BLOCKED",
    stream_id = stream_id,
    maximum_stream_data = maximum_stream_data
  }, offset
end
local parse_streams_blocked_frame
parse_streams_blocked_frame = function(data, offset, frame_type)
  local maximum_streams, err
  maximum_streams, offset, err = parse_varint_required(data, offset, "STREAMS_BLOCKED maximum_streams")
  if not (maximum_streams ~= nil) then
    return nil, offset, err
  end
  local name = frame_type == 0x16 and "STREAMS_BLOCKED_BIDI" or "STREAMS_BLOCKED_UNI"
  return {
    type = frame_type,
    name = name,
    maximum_streams = maximum_streams
  }, offset
end
local parse_new_connection_id_frame
parse_new_connection_id_frame = function(data, offset)
  local sequence_number, err
  sequence_number, offset, err = parse_varint_required(data, offset, "NEW_CONNECTION_ID sequence_number")
  if not (sequence_number ~= nil) then
    return nil, offset, err
  end
  local retire_prior_to
  retire_prior_to, offset, err = parse_varint_required(data, offset, "NEW_CONNECTION_ID retire_prior_to")
  if not (retire_prior_to ~= nil) then
    return nil, offset, err
  end
  if not (need_bytes(data, offset, 1)) then
    return nil, offset, "truncated NEW_CONNECTION_ID cid_length"
  end
  local cid_length = su("B", data, offset)
  offset = offset + 1
  if not (need_bytes(data, offset, cid_length)) then
    return nil, offset, "NEW_CONNECTION_ID connection_id exceeds frame data"
  end
  local connection_id = data:sub(offset, offset + cid_length - 1)
  offset = offset + cid_length
  if not (need_bytes(data, offset, 16)) then
    return nil, offset, "NEW_CONNECTION_ID stateless_reset_token exceeds frame data"
  end
  local stateless_reset_token = data:sub(offset, offset + 15)
  offset = offset + 16
  return {
    type = 0x18,
    name = "NEW_CONNECTION_ID",
    sequence_number = sequence_number,
    retire_prior_to = retire_prior_to,
    cid_length = cid_length,
    connection_id = connection_id,
    stateless_reset_token = stateless_reset_token
  }, offset
end
local parse_retire_connection_id_frame
parse_retire_connection_id_frame = function(data, offset)
  local sequence_number, err
  sequence_number, offset, err = parse_varint_required(data, offset, "RETIRE_CONNECTION_ID sequence_number")
  if not (sequence_number ~= nil) then
    return nil, offset, err
  end
  return {
    type = 0x19,
    name = "RETIRE_CONNECTION_ID",
    sequence_number = sequence_number
  }, offset
end
local parse_path_challenge_frame
parse_path_challenge_frame = function(data, offset)
  if not (need_bytes(data, offset, 8)) then
    return nil, offset, "PATH_CHALLENGE requires 8 bytes"
  end
  local path_data = data:sub(offset, offset + 7)
  return {
    type = 0x1a,
    name = "PATH_CHALLENGE",
    data = path_data
  }, offset + 8
end
local parse_path_response_frame
parse_path_response_frame = function(data, offset)
  if not (need_bytes(data, offset, 8)) then
    return nil, offset, "PATH_RESPONSE requires 8 bytes"
  end
  local path_data = data:sub(offset, offset + 7)
  return {
    type = 0x1b,
    name = "PATH_RESPONSE",
    data = path_data
  }, offset + 8
end
local parse_connection_close_frame
parse_connection_close_frame = function(data, offset, frame_type)
  local error_code, err
  error_code, offset, err = parse_varint_required(data, offset, "CONNECTION_CLOSE error_code")
  if not (error_code ~= nil) then
    return nil, offset, err
  end
  local frame_type_field
  if frame_type == 0x1c then
    frame_type_field, offset, err = parse_varint_required(data, offset, "CONNECTION_CLOSE frame_type")
    if not (frame_type_field ~= nil) then
      return nil, offset, err
    end
  end
  local reason_length
  reason_length, offset, err = parse_varint_required(data, offset, "CONNECTION_CLOSE reason_length")
  if not (reason_length ~= nil) then
    return nil, offset, err
  end
  if not (need_bytes(data, offset, reason_length)) then
    return nil, offset, "CONNECTION_CLOSE reason exceeds frame data"
  end
  local reason_phrase = data:sub(offset, offset + reason_length - 1)
  local name = frame_type == 0x1c and "CONNECTION_CLOSE" or "CONNECTION_CLOSE_APP"
  return {
    type = frame_type,
    name = name,
    error_code = error_code,
    frame_type = frame_type_field,
    reason_length = reason_length,
    reason_phrase = reason_phrase
  }, offset + reason_length
end
local parse_handshake_done_frame
parse_handshake_done_frame = function(data, offset)
  return {
    type = 0x1e,
    name = "HANDSHAKE_DONE"
  }, offset
end
local parse_frame
parse_frame = function(data, offset)
  if offset > #data then
    return nil, offset
  end
  local frame_type, new_offset = parse_varint(data, offset)
  if not (frame_type) then
    return nil, offset, "truncated frame type varint"
  end
  local parser
  local _exp_0 = frame_type
  if 0x00 == _exp_0 then
    parser = parse_padding_frame
  elseif 0x01 == _exp_0 then
    parser = parse_ping_frame
  elseif 0x02 == _exp_0 or 0x03 == _exp_0 then
    parser = function(d, o)
      return parse_ack_frame(d, o, frame_type)
    end
  elseif 0x04 == _exp_0 then
    parser = parse_reset_stream_frame
  elseif 0x05 == _exp_0 then
    parser = parse_stop_sending_frame
  elseif 0x06 == _exp_0 then
    parser = parse_crypto_frame
  elseif 0x07 == _exp_0 then
    parser = parse_new_token_frame
  elseif 0x10 == _exp_0 then
    parser = parse_max_data_frame
  elseif 0x11 == _exp_0 then
    parser = parse_max_stream_data_frame
  elseif 0x12 == _exp_0 or 0x13 == _exp_0 then
    parser = function(d, o)
      return parse_max_streams_frame(d, o, frame_type)
    end
  elseif 0x14 == _exp_0 then
    parser = parse_data_blocked_frame
  elseif 0x15 == _exp_0 then
    parser = parse_stream_data_blocked_frame
  elseif 0x16 == _exp_0 or 0x17 == _exp_0 then
    parser = function(d, o)
      return parse_streams_blocked_frame(d, o, frame_type)
    end
  elseif 0x18 == _exp_0 then
    parser = parse_new_connection_id_frame
  elseif 0x19 == _exp_0 then
    parser = parse_retire_connection_id_frame
  elseif 0x1a == _exp_0 then
    parser = parse_path_challenge_frame
  elseif 0x1b == _exp_0 then
    parser = parse_path_response_frame
  elseif 0x1c == _exp_0 or 0x1d == _exp_0 then
    parser = function(d, o)
      return parse_connection_close_frame(d, o, frame_type)
    end
  elseif 0x1e == _exp_0 then
    parser = parse_handshake_done_frame
  else
    if frame_type >= 0x08 and frame_type <= 0x0f then
      parser = function(d, o)
        return parse_stream_frame(d, o, frame_type)
      end
    else
      parser = nil
    end
  end
  if not (parser) then
    return {
      type = frame_type,
      name = "UNKNOWN"
    }, new_offset
  end
  local frame, parsed_off, err = parser(data, new_offset)
  if not (frame) then
    return nil, offset, err
  end
  return frame, parsed_off
end
local iter_frames
iter_frames = function(payload_data)
  local offset = 1
  return function()
    if offset > #payload_data then
      return nil
    end
    local frame, new_offset = parse_frame(payload_data, offset)
    if not (frame) then
      return nil
    end
    offset = new_offset
    return frame
  end
end
local validate_frames
validate_frames = function(payload_data)
  local offset = 1
  local frame_count = 0
  while offset <= #payload_data do
    local frame, new_offset, err = parse_frame(payload_data, offset)
    if not (frame) then
      return false, err or "Failed to parse frame at offset " .. tostring(offset)
    end
    if new_offset <= offset then
      return false, "Frame parser did not advance at offset " .. tostring(offset)
    end
    offset = new_offset
    frame_count = frame_count + 1
    if frame_count > 1000 then
      return false, "Too many frames (possible parsing error)"
    end
  end
  return true, tostring(frame_count) .. " frames validated"
end
return {
  parse_frame = parse_frame,
  parse_crypto_frame = parse_crypto_frame,
  parse_stream_frame = parse_stream_frame,
  parse_ack_frame = parse_ack_frame,
  iter_frames = iter_frames,
  validate_frames = validate_frames,
  parse_varint = parse_varint,
  encode_varint = encode_varint,
  frame_types = frame_types
}
