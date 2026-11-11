local util = require("ipparse.lib.util")
local test
test = util.test
local parse_frame, iter_frames, validate_frames, encode_varint, parse_varint
do
  local _obj_0 = require("ipparse.l4.quic.frames")
  parse_frame, iter_frames, validate_frames, encode_varint, parse_varint = _obj_0.parse_frame, _obj_0.iter_frames, _obj_0.validate_frames, _obj_0.encode_varint, _obj_0.parse_varint
end
test("frame: PADDING parsed", function()
  local f, off = parse_frame("\000", 1)
  return assert(f.type == 0x00 and f.name == "PADDING", "expected PADDING")
end)
test("frame: PING parsed", function()
  local f, off = parse_frame("\001", 1)
  return assert(f.type == 0x01 and f.name == "PING", "expected PING")
end)
test("frame: ACK minimal parsed", function()
  local data = "\002\000\000\000\000"
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x02 and f.name == "ACK")
  return assert(f.largest_acked == 0)
end)
test("frame: CRYPTO frame parsed", function()
  local payload = "hello"
  local data = "\006" .. encode_varint(0) .. encode_varint(#payload) .. payload
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x06 and f.name == "CRYPTO")
  assert(f.data == payload, "crypto data mismatch")
  return assert(f.length == 5)
end)
test("frame: STREAM frame parsed", function()
  local payload = "world"
  local data = "\014" .. encode_varint(1) .. encode_varint(0) .. encode_varint(#payload) .. payload
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x0E and f.name == "STREAM")
  assert(f.id == 1)
  return assert(f.data == payload)
end)
test("frame: RESET_STREAM parsed", function()
  local data = "\004" .. encode_varint(3) .. encode_varint(0) .. encode_varint(100)
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x04 and f.name == "RESET_STREAM")
  return assert(f.stream_id == 3 and f.final_size == 100)
end)
test("frame: STOP_SENDING parsed", function()
  local data = "\005" .. encode_varint(7) .. encode_varint(42)
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x05 and f.name == "STOP_SENDING")
  return assert(f.stream_id == 7 and f.app_error_code == 42)
end)
test("frame: MAX_DATA parsed", function()
  local data = "\016" .. encode_varint(1000)
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x10 and f.name == "MAX_DATA")
  return assert(f.maximum_data == 1000)
end)
test("frame: MAX_STREAM_DATA parsed", function()
  local data = "\017" .. encode_varint(2) .. encode_varint(2000)
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x11 and f.name == "MAX_STREAM_DATA")
  return assert(f.stream_id == 2 and f.maximum_stream_data == 2000)
end)
test("frame: MAX_STREAMS_BIDI parsed", function()
  local data = "\018" .. encode_varint(10)
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x12 and f.name == "MAX_STREAMS_BIDI")
  return assert(f.maximum_streams == 10)
end)
test("frame: DATA_BLOCKED parsed", function()
  local data = "\020" .. encode_varint(500)
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x14 and f.name == "DATA_BLOCKED")
  return assert(f.maximum_data == 500)
end)
test("frame: NEW_CONNECTION_ID parsed", function()
  local cid = "\170\187\204\221\238\255\017\034"
  local rst = string.rep("\000", 16)
  local data = "\024" .. encode_varint(1) .. encode_varint(0) .. "\008" .. cid .. rst
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x18 and f.name == "NEW_CONNECTION_ID")
  assert(f.sequence_number == 1)
  return assert(f.connection_id == cid)
end)
test("frame: RETIRE_CONNECTION_ID parsed", function()
  local data = "\025" .. encode_varint(5)
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x19 and f.name == "RETIRE_CONNECTION_ID")
  return assert(f.sequence_number == 5)
end)
test("frame: PATH_CHALLENGE parsed", function()
  local data = "\026" .. string.rep("\171", 8)
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x1a and f.name == "PATH_CHALLENGE")
  return assert(#f.data == 8)
end)
test("frame: PATH_RESPONSE parsed", function()
  local data = "\027" .. string.rep("\205", 8)
  local f, _ = parse_frame(data, 1)
  return assert(f.type == 0x1b and f.name == "PATH_RESPONSE")
end)
test("frame: CONNECTION_CLOSE parsed", function()
  local reason = "test error"
  local data = "\028" .. encode_varint(0) .. encode_varint(0) .. encode_varint(#reason) .. reason
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x1c and f.name == "CONNECTION_CLOSE")
  return assert(f.reason_phrase == reason)
end)
test("frame: HANDSHAKE_DONE parsed", function()
  local f, _ = parse_frame("\030", 1)
  return assert(f.type == 0x1e and f.name == "HANDSHAKE_DONE")
end)
test("frame: CRYPTO truncated payload returns nil", function()
  local data = "\006\000\005\170"
  local f, _, err = parse_frame(data, 1)
  assert(f == nil, "expected parse failure")
  return assert(err and err:match("CRYPTO"), "expected CRYPTO error, got " .. tostring(err))
end)
test("frame: PATH_CHALLENGE truncated returns nil", function()
  local f, _, err = parse_frame("\026\170", 1)
  assert(f == nil, "expected parse failure")
  return assert(err and err:match("PATH_CHALLENGE"), "expected PATH_CHALLENGE error, got " .. tostring(err))
end)
test("frame: iter_frames over two frames", function()
  local data = "\001\001"
  local count = 0
  for f in iter_frames(data) do
    count = count + 1
  end
  return assert(count == 2, "expected 2 frames, got " .. tostring(count))
end)
test("frame: validate_frames succeeds on valid data", function()
  local data = "\001\001"
  local ok, msg = validate_frames(data)
  return assert(ok == true, "expected valid, got: " .. tostring(msg))
end)
test("frame: validate_frames fails on malformed data", function()
  local data = "\006\000\005\170"
  local ok, msg = validate_frames(data)
  assert(ok == false, "expected invalid data")
  return assert(msg and msg:match("CRYPTO"), "expected CRYPTO validation error, got " .. tostring(msg))
end)
test("frame: UNKNOWN frame does not get stuck", function()
  local data = "\032\001"
  local f1, off1 = parse_frame(data, 1)
  assert(f1.name == "UNKNOWN", "expected UNKNOWN, got " .. tostring(f1.name))
  local f2, off2 = parse_frame(data, off1)
  return assert(f2.name == "PING", "expected PING after UNKNOWN, got " .. tostring(f2.name))
end)
test("frame: type-dependent parsers dispatch correctly", function()
  local data = "\003\000\000\000\000\000\000\000"
  local f, _ = parse_frame(data, 1)
  assert(f.type == 0x03 and f.name == "ACK_ECN", "expected ACK_ECN")
  f, _ = parse_frame("\019\001", 1)
  assert(f.type == 0x13 and f.name == "MAX_STREAMS_UNI", "expected MAX_STREAMS_UNI")
  f, _ = parse_frame("\022\001", 1)
  assert(f.type == 0x16 and f.name == "STREAMS_BLOCKED_BIDI", "expected STREAMS_BLOCKED_BIDI")
  f, _ = parse_frame("\023\001", 1)
  assert(f.type == 0x17 and f.name == "STREAMS_BLOCKED_UNI", "expected STREAMS_BLOCKED_UNI")
  f, _ = parse_frame("\029\000\000", 1)
  assert(f.type == 0x1d and f.name == "CONNECTION_CLOSE_APP", "expected CONNECTION_CLOSE_APP")
  for t = 0x08, 0x0f do
    f, _ = parse_frame((string.char(t) .. "\001\000\000\000"), 1)
    assert(f and f.type == t and f.name == "STREAM", "expected STREAM for type " .. tostring(t))
  end
end)
test("frame: PADDING run coalesced into one frame", function()
  local data = string.rep("\000", 1000)
  local count = 0
  local f = nil
  for frame in iter_frames(data) do
    count = count + 1
    f = frame
  end
  assert(count == 1, "expected 1 PADDING frame, got " .. tostring(count))
  assert(f.type == 0x00 and f.name == "PADDING", "expected PADDING")
  return assert(f.length == 1000, "expected length 1000, got " .. tostring(f.length))
end)
test("frame: PADDING run interrupted by other frames", function()
  local data = "\000\000\001\000"
  local frames = { }
  for frame in iter_frames(data) do
    frames[#frames + 1] = frame
  end
  assert(#frames == 3, "expected 3 frames, got " .. tostring(#frames))
  assert(frames[1].name == "PADDING" and frames[1].length == 2, "expected PADDING(2)")
  assert(frames[2].name == "PING", "expected PING")
  return assert(frames[3].name == "PADDING" and frames[3].length == 1, "expected PADDING(1)")
end)
test("frame: validate_frames counts a PADDING run once", function()
  local ok, msg = validate_frames(string.rep("\000", 1000))
  assert(ok == true, "expected valid, got: " .. tostring(msg))
  return assert(msg:match("1 frames validated"), "expected 1 frame, got: " .. tostring(msg))
end)
test("frame: encode_varint four sizes round-trip", function()
  local _list_0 = {
    63,
    16383,
    1073741823,
    1073741824
  }
  for _index_0 = 1, #_list_0 do
    local value = _list_0[_index_0]
    local enc = encode_varint(value)
    assert(#enc >= 1 and #enc <= 8, "bad length " .. tostring(#enc) .. " for " .. tostring(value))
    local dec, off = parse_varint(enc, 1)
    assert(dec == value, "expected " .. tostring(value) .. ", got " .. tostring(dec))
    assert(off == #enc + 1, "offset should be past the varint")
  end
end)
test("frame: parse_varint truncated inputs return nil", function()
  local cases = {
    {
      "",
      1
    },
    {
      "\064",
      1
    },
    {
      "\128\000\000",
      1
    },
    {
      "\192\000\000\000\000\000\000",
      1
    }
  }
  for _index_0 = 1, #cases do
    local c = cases[_index_0]
    local v, off = parse_varint(c[1], c[2])
    assert(v == nil, "expected nil for truncated varint")
    assert(off == c[2], "offset should be unchanged")
  end
end)
test("frame: parse_frame on empty input returns nil", function()
  local f, off = parse_frame("", 1)
  return assert(f == nil and off == 1, "expected nil at offset 1")
end)
test("frame: parse_frame truncated frame type varint", function()
  local f, _, err = parse_frame("\064", 1)
  assert(f == nil, "expected nil frame")
  return assert(err and err:match("truncated frame type"), "expected truncated type error, got " .. tostring(err))
end)
test("frame: ACK with one range parses gap and length", function()
  local data = "\002\000\000\001\000\000\005"
  local f, off = parse_frame(data, 1)
  assert(f and f.name == "ACK", "expected ACK")
  assert(f.ack_range_count == 1, "expected 1 range")
  assert(#f.ack_ranges == 1, "expected one parsed range")
  assert(f.ack_ranges[1].gap == 0 and f.ack_ranges[1].length == 5, "range mismatch")
  return assert(off == #data + 1, "offset should be past the frame")
end)
test("frame: ACK truncated fields return nil", function()
  local cases = {
    {
      "\002"
    },
    {
      "\002\000"
    },
    {
      "\002\000\000"
    },
    {
      "\002\000\000\000\000"
    }
  }
  for i = 1, 3 do
    local f, _, err = parse_frame(cases[i][1], 1)
    assert(f == nil and err, "expected truncation for case " .. tostring(i))
  end
  local f = parse_frame(cases[4][1], 1)
  return assert(f and f.name == "ACK", "four zero varints should parse")
end)
test("frame: ACK range count too large rejected", function()
  local f, _, err = parse_frame("\002\000\000\005\000", 1)
  assert(f == nil, "expected nil frame")
  return assert(err and err:match("ack_range_count"), "expected range count error, got " .. tostring(err))
end)
test("frame: ACK_ECN truncated ECN counters return nil", function()
  local base = "\003\000\000\000\000"
  for i = 1, 3 do
    local f, _, err = parse_frame(base .. string.rep("\000", i - 1), 1)
    assert(f == nil and err, "expected truncation for ECN counter " .. tostring(i))
  end
end)
test("frame: RESET_STREAM truncated fields return nil", function()
  local _list_0 = {
    "\004",
    "\004\001",
    "\004\001\001"
  }
  for _index_0 = 1, #_list_0 do
    local data = _list_0[_index_0]
    local f, _, err = parse_frame(data, 1)
    assert(f == nil and err, "expected truncation for RESET_STREAM")
  end
end)
test("frame: STOP_SENDING truncated fields return nil", function()
  local _list_0 = {
    "\005",
    "\005\001"
  }
  for _index_0 = 1, #_list_0 do
    local data = _list_0[_index_0]
    local f, _, err = parse_frame(data, 1)
    assert(f == nil and err, "expected truncation for STOP_SENDING")
  end
end)
test("frame: CRYPTO truncated offset and length return nil", function()
  local _list_0 = {
    "\006",
    "\006\000"
  }
  for _index_0 = 1, #_list_0 do
    local data = _list_0[_index_0]
    local f, _, err = parse_frame(data, 1)
    assert(f == nil and err, "expected truncation for CRYPTO")
  end
end)
test("frame: NEW_TOKEN parsed", function()
  local token = "tok123"
  local data = "\007" .. encode_varint(#token) .. token
  local f, off = parse_frame(data, 1)
  assert(f and f.name == "NEW_TOKEN", "expected NEW_TOKEN")
  assert(f.token == token and f.token_length == #token, "token mismatch")
  return assert(off == #data + 1, "offset should be past the frame")
end)
test("frame: NEW_TOKEN truncated length and payload return nil", function()
  local f, _, err = parse_frame("\007", 1)
  assert(f == nil and err, "expected truncated length error")
  f, _, err = parse_frame("\007\005ab", 1)
  assert(f == nil, "expected nil on short payload")
  return assert(err and err:match("NEW_TOKEN"), "expected NEW_TOKEN error, got " .. tostring(err))
end)
test("frame: STREAM variants without offset/length and with FIN", function()
  local f, _ = parse_frame("\008\001abc", 1)
  assert(f and f.name == "STREAM", "expected STREAM")
  assert(f.offset == 0 and f.data == "abc" and f.fin == false, "0x08 mismatch")
  f, _ = parse_frame("\009\001abc", 1)
  assert(f.fin == true, "0x09 should set fin")
  f, _ = parse_frame(("\010\001\003abc"), 1)
  assert(f.offset == 0 and f.length == 3 and f.data == "abc", "0x0a mismatch")
  f, _ = parse_frame(("\012\001\007abc"), 1)
  assert(f.offset == 7 and f.data == "abc", "0x0c mismatch")
  f, _ = parse_frame(("\015\001\007\003abc"), 1)
  return assert(f.offset == 7 and f.length == 3 and f.fin == true, "0x0f mismatch")
end)
test("frame: STREAM truncated fields and payload return nil", function()
  local _list_0 = {
    "\014",
    "\014\001",
    "\014\001\000",
    "\014\001\000\005ab"
  }
  for _index_0 = 1, #_list_0 do
    local data = _list_0[_index_0]
    local f, _, err = parse_frame(data, 1)
    assert(f == nil and err, "expected STREAM truncation")
  end
end)
test("frame: MAX_DATA truncated returns nil", function()
  local f, _, err = parse_frame("\016", 1)
  return assert(f == nil and err, "expected MAX_DATA truncation")
end)
test("frame: MAX_STREAM_DATA truncated fields return nil", function()
  local _list_0 = {
    "\017",
    "\017\001"
  }
  for _index_0 = 1, #_list_0 do
    local data = _list_0[_index_0]
    local f, _, err = parse_frame(data, 1)
    assert(f == nil and err, "expected MAX_STREAM_DATA truncation")
  end
end)
test("frame: MAX_STREAMS truncated returns nil", function()
  local _list_0 = {
    "\018",
    "\019"
  }
  for _index_0 = 1, #_list_0 do
    local t = _list_0[_index_0]
    local f, _, err = parse_frame(t, 1)
    assert(f == nil and err, "expected MAX_STREAMS truncation")
  end
end)
test("frame: DATA_BLOCKED truncated returns nil", function()
  local f, _, err = parse_frame("\020", 1)
  return assert(f == nil and err, "expected DATA_BLOCKED truncation")
end)
test("frame: STREAM_DATA_BLOCKED parsed and truncated", function()
  local data = "\021" .. encode_varint(4) .. encode_varint(900)
  local f, off = parse_frame(data, 1)
  assert(f and f.name == "STREAM_DATA_BLOCKED", "expected STREAM_DATA_BLOCKED")
  assert(f.stream_id == 4 and f.maximum_stream_data == 900, "fields mismatch")
  assert(off == #data + 1, "offset should be past the frame")
  local _list_0 = {
    "\021",
    "\021\004"
  }
  for _index_0 = 1, #_list_0 do
    local bad = _list_0[_index_0]
    local _, err
    f, _, err = parse_frame(bad, 1)
    assert(f == nil and err, "expected STREAM_DATA_BLOCKED truncation")
  end
end)
test("frame: STREAMS_BLOCKED truncated returns nil", function()
  local _list_0 = {
    "\022",
    "\023"
  }
  for _index_0 = 1, #_list_0 do
    local t = _list_0[_index_0]
    local f, _, err = parse_frame(t, 1)
    assert(f == nil and err, "expected STREAMS_BLOCKED truncation")
  end
end)
test("frame: NEW_CONNECTION_ID truncated fields return nil", function()
  local cases = {
    "\024",
    "\024\001",
    "\024\001\000\004\001\002",
    "\024\001\000\001\170"
  }
  for i = 1, #cases do
    local f, _, err = parse_frame(cases[i], 1)
    assert(f == nil and err, "expected NEW_CONNECTION_ID truncation for case " .. tostring(i))
  end
end)
test("frame: RETIRE_CONNECTION_ID truncated returns nil", function()
  local f, _, err = parse_frame("\025", 1)
  return assert(f == nil and err, "expected RETIRE_CONNECTION_ID truncation")
end)
test("frame: PATH_RESPONSE truncated returns nil", function()
  local f, _, err = parse_frame("\027\170", 1)
  assert(f == nil, "expected nil frame")
  return assert(err and err:match("PATH_RESPONSE"), "expected PATH_RESPONSE error, got " .. tostring(err))
end)
test("frame: CONNECTION_CLOSE truncated fields return nil", function()
  local _list_0 = {
    "\028",
    "\028\000",
    "\028\000\000"
  }
  for _index_0 = 1, #_list_0 do
    local data = _list_0[_index_0]
    local f, _, err = parse_frame(data, 1)
    assert(f == nil and err, "expected CONNECTION_CLOSE truncation")
  end
  local f, _, err = parse_frame("\028\000\000\005ab", 1)
  assert(f == nil, "expected nil on short reason")
  assert(err and err:match("CONNECTION_CLOSE"), "expected CONNECTION_CLOSE error, got " .. tostring(err))
  local _list_1 = {
    "\029",
    "\029\000"
  }
  for _index_0 = 1, #_list_1 do
    local data = _list_1[_index_0]
    f, _, err = parse_frame(data, 1)
    assert(f == nil and err, "expected CONNECTION_CLOSE_APP truncation")
  end
end)
test("frame: iter_frames stops on a malformed frame", function()
  local count = 0
  for f in iter_frames("\006") do
    count = count + 1
  end
  return assert(count == 0, "expected no frames from malformed data, got " .. tostring(count))
end)
return util.summary("frames")
