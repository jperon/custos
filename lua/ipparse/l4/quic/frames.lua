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
    return lshift(band(high, 0x3FFFFFFF), 32) + low, offset + 8
  end
end
local encode_varint
encode_varint = function(value)
  if value < 64 then
    return sp("B", value)
  elseif value < 16384 then
    return sp(">H", bor(0x4000, value))
  elseif value < 1073741824 then
    return sp(">I4", bor(0x80000000, value))
  else
    local high = band(rshift(value, 32), 0x3FFFFFFF)
    local low = band(value, 0xFFFFFFFF)
    return sp(">I4I4", bor(0xC0000000, high), low)
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
  local largest_acked
  largest_acked, offset = parse_varint(data, offset)
  local ack_delay
  ack_delay, offset = parse_varint(data, offset)
  local ack_range_count
  ack_range_count, offset = parse_varint(data, offset)
  local first_ack_range
  first_ack_range, offset = parse_varint(data, offset)
  local ack_ranges = { }
  for i = 1, ack_range_count do
    local gap
    gap, offset = parse_varint(data, offset)
    local ack_range_len
    ack_range_len, offset = parse_varint(data, offset)
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
    frame.ect0_count, offset = parse_varint(data, offset)
    frame.ect1_count, offset = parse_varint(data, offset)
    frame.ecn_ce_count, offset = parse_varint(data, offset)
  end
  return frame, offset
end
local parse_crypto_frame
parse_crypto_frame = function(data, offset)
  local crypto_offset
  crypto_offset, offset = parse_varint(data, offset)
  local length
  length, offset = parse_varint(data, offset)
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
  local stream_id
  stream_id, offset = parse_varint(data, offset)
  local stream_offset = 0
  if band(frame_type, 0x04) ~= 0 then
    stream_offset, offset = parse_varint(data, offset)
  end
  local length
  if band(frame_type, 0x02) ~= 0 then
    length, offset = parse_varint(data, offset)
  else
    length = #data - offset + 1
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
  local token_length
  token_length, offset = parse_varint(data, offset)
  local token = data:sub(offset, offset + token_length - 1)
  local frame = {
    type = 0x07,
    name = "NEW_TOKEN",
    token_length = token_length,
    token = token
  }
  return frame, offset + token_length
end
local parse_frame
parse_frame = function(data, offset)
  if offset > #data then
    return nil, offset
  end
  local frame_type, new_offset = parse_varint(data, offset)
  if not (frame_type) then
    return nil, offset
  end
  local _exp_0 = frame_type
  if 0x00 == _exp_0 then
    return parse_padding_frame(data, new_offset)
  elseif 0x01 == _exp_0 then
    return parse_ping_frame(data, new_offset)
  elseif 0x02 == _exp_0 or 0x03 == _exp_0 then
    return parse_ack_frame(data, new_offset, frame_type)
  elseif 0x06 == _exp_0 then
    return parse_crypto_frame(data, new_offset)
  elseif 0x07 == _exp_0 then
    return parse_new_token_frame(data, new_offset)
  else
    if frame_type >= 0x08 and frame_type <= 0x0f then
      return parse_stream_frame(data, new_offset, frame_type)
    else
      local frame = {
        type = frame_type,
        name = frame_types[frame_type] or "UNKNOWN",
        raw_data = data:sub(new_offset)
      }
      return frame, #data + 1
    end
  end
end
local iter_frames
iter_frames = function(payload_data)
  local offset = 1
  return function()
    if offset > #payload_data then
      return nil
    end
    local frame, new_offset = parse_frame(payload_data, offset)
    offset = new_offset
    return frame
  end
end
local validate_frames
validate_frames = function(payload_data)
  local offset = 1
  local frame_count = 0
  while offset <= #payload_data do
    local frame, new_offset = parse_frame(payload_data, offset)
    if not (frame) then
      return false, "Failed to parse frame at offset " .. tostring(offset)
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
