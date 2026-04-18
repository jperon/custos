#!/usr/bin/env moon

--- Test QUIC Frame Parsing
-- Tests the frame parsing module with sample frame data

frames = require "ipparse.l4.quic.frames"
:bin2hex, :hex2bin = require "ipparse.init"

print "=== Testing QUIC Frame Parsing ==="
print ""

-- Test VarInt parsing
print "=== VarInt Tests ==="
test_varints = {
  {hex: "00", expected: 0, desc: "Single byte - 0"}
  {hex: "25", expected: 37, desc: "Single byte - 37"}
  {hex: "4001", expected: 1, desc: "Two bytes - 1"}
  {hex: "7fff", expected: 16383, desc: "Two bytes - max"}
  {hex: "80000001", expected: 1, desc: "Four bytes - 1"}
  {hex: "c0000001", expected: 1, desc: "Eight bytes - 1"}
}

for test in *test_varints
  data = hex2bin test.hex
  value, offset = frames.parse_varint data, 1

  if value and value == test.expected and offset == #data + 1
    print "✓ #{test.desc}: #{value}"
  else
    print "✗ #{test.desc}: got #{value or "nil"}, expected #{test.expected}"

print ""

-- Test VarInt encoding
print "=== VarInt Encoding Tests ==="
for test in *test_varints
  encoded = frames.encode_varint test.expected
  encoded_hex = bin2hex encoded

  if encoded_hex == test.hex
    print "✓ Encode #{test.expected}: #{encoded_hex}"
  else
    print "✗ Encode #{test.expected}: got #{encoded_hex}, expected #{test.hex}"

print ""

-- Test frame parsing with sample data
print "=== Frame Parsing Tests ==="

-- Test PADDING frame (type 0x00)
print "--- PADDING Frame ---"
padding_data = hex2bin "00"
frame, offset = frames.parse_frame padding_data, 1
if frame and frame.type == 0x00 and frame.name == "PADDING"
  print "✓ PADDING frame parsed correctly"
else
  print "✗ PADDING frame parsing failed"

-- Test PING frame (type 0x01)
print "--- PING Frame ---"
ping_data = hex2bin "01"
frame, offset = frames.parse_frame ping_data, 1
if frame and frame.type == 0x01 and frame.name == "PING"
  print "✓ PING frame parsed correctly"
else
  print "✗ PING frame parsing failed"

-- Test CRYPTO frame (type 0x06)
print "--- CRYPTO Frame ---"
-- Frame type (0x06) + offset (0x00) + length (0x10) + 16 bytes of data
crypto_hex = "06" .. "00" .. "10" .. "0102030405060708090a0b0c0d0e0f10"
crypto_data = hex2bin crypto_hex
frame, offset = frames.parse_frame crypto_data, 1

if frame and frame.type == 0x06 and frame.name == "CRYPTO"
  print "✓ CRYPTO frame parsed correctly"
  print "  Offset: #{frame.offset}"
  print "  Length: #{frame.length}"
  print "  Data: #{bin2hex frame.data}"

  if frame.offset == 0 and frame.length == 16 and #frame.data == 16
    print "✓ CRYPTO frame fields correct"
  else
    print "✗ CRYPTO frame fields incorrect"
else
  print "✗ CRYPTO frame parsing failed"

-- Test STREAM frame (type 0x08)
print "--- STREAM Frame ---"
-- Frame type (0x08) + stream_id (0x04) + data ("hello")
stream_hex = "08" .. "04" .. "68656c6c6f"  -- "hello" in hex
stream_data = hex2bin stream_hex
frame, offset = frames.parse_frame stream_data, 1

if frame and frame.type == 0x08 and frame.name == "STREAM"
  print "✓ STREAM frame parsed correctly"
  print "  Stream ID: #{frame.id}"
  print "  Offset: #{frame.offset}"
  print "  Length: #{frame.length}"
  print "  Data: #{frame.data}"
  print "  FIN: #{frame.fin}"
else
  print "✗ STREAM frame parsing failed"

-- Test multiple frames
print ""
print "=== Multiple Frame Parsing ==="
multi_hex = "00" .. "01" .. crypto_hex  -- PADDING + PING + CRYPTO
multi_data = hex2bin multi_hex

frames_found = {}
for frame in frames.iter_frames multi_data
  frames_found[#frames_found + 1] = frame
  print "Found #{frame.name} frame (type #{string.format "0x%02x", frame.type})"

if #frames_found == 3
  print "✓ Parsed #{#frames_found} frames correctly"
else
  print "✗ Expected 3 frames, got #{#frames_found}"

-- Test frame validation
print ""
print "=== Frame Validation ==="
valid, msg = frames.validate_frames multi_data
if valid
  print "✓ Frame validation passed: #{msg}"
else
  print "✗ Frame validation failed: #{msg}"

print ""
print "=== Frame Types Reference ==="
print "Supported frame types:"
for code, name in pairs frames.frame_types
  if type(code) == "number"
    print "  0x#{string.format "%02x", code}: #{name}"

print ""
print "=== Frame Parsing Tests Complete ==="
