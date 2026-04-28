local frames = require("ipparse.l4.quic.frames")
local bin2hex, hex2bin
do
  local _obj_0 = require("ipparse.init")
  bin2hex, hex2bin = _obj_0.bin2hex, _obj_0.hex2bin
end
print("=== Testing QUIC Frame Parsing ===")
print("")
print("=== VarInt Tests ===")
local test_varints = {
  {
    hex = "00",
    expected = 0,
    desc = "Single byte - 0"
  },
  {
    hex = "25",
    expected = 37,
    desc = "Single byte - 37"
  },
  {
    hex = "4001",
    expected = 1,
    desc = "Two bytes - 1"
  },
  {
    hex = "7fff",
    expected = 16383,
    desc = "Two bytes - max"
  },
  {
    hex = "80000001",
    expected = 1,
    desc = "Four bytes - 1"
  },
  {
    hex = "c0000001",
    expected = 1,
    desc = "Eight bytes - 1"
  }
}
for _index_0 = 1, #test_varints do
  local test = test_varints[_index_0]
  local data = hex2bin(test.hex)
  local value, offset = frames.parse_varint(data, 1)
  if value and value == test.expected and offset == #data + 1 then
    print("✓ " .. tostring(test.desc) .. ": " .. tostring(value))
  else
    print("✗ " .. tostring(test.desc) .. ": got " .. tostring(value or "nil") .. ", expected " .. tostring(test.expected))
  end
end
print("")
print("=== VarInt Encoding Tests ===")
for _index_0 = 1, #test_varints do
  local test = test_varints[_index_0]
  local encoded = frames.encode_varint(test.expected)
  local encoded_hex = bin2hex(encoded)
  if encoded_hex == test.hex then
    print("✓ Encode " .. tostring(test.expected) .. ": " .. tostring(encoded_hex))
  else
    print("✗ Encode " .. tostring(test.expected) .. ": got " .. tostring(encoded_hex) .. ", expected " .. tostring(test.hex))
  end
end
print("")
print("=== Frame Parsing Tests ===")
print("--- PADDING Frame ---")
local padding_data = hex2bin("00")
local frame, offset = frames.parse_frame(padding_data, 1)
if frame and frame.type == 0x00 and frame.name == "PADDING" then
  print("✓ PADDING frame parsed correctly")
else
  print("✗ PADDING frame parsing failed")
end
print("--- PING Frame ---")
local ping_data = hex2bin("01")
frame, offset = frames.parse_frame(ping_data, 1)
if frame and frame.type == 0x01 and frame.name == "PING" then
  print("✓ PING frame parsed correctly")
else
  print("✗ PING frame parsing failed")
end
print("--- CRYPTO Frame ---")
local crypto_hex = "06" .. "00" .. "10" .. "0102030405060708090a0b0c0d0e0f10"
local crypto_data = hex2bin(crypto_hex)
frame, offset = frames.parse_frame(crypto_data, 1)
if frame and frame.type == 0x06 and frame.name == "CRYPTO" then
  print("✓ CRYPTO frame parsed correctly")
  print("  Offset: " .. tostring(frame.offset))
  print("  Length: " .. tostring(frame.length))
  print("  Data: " .. tostring(bin2hex(frame.data)))
  if frame.offset == 0 and frame.length == 16 and #frame.data == 16 then
    print("✓ CRYPTO frame fields correct")
  else
    print("✗ CRYPTO frame fields incorrect")
  end
else
  print("✗ CRYPTO frame parsing failed")
end
print("--- STREAM Frame ---")
local stream_hex = "08" .. "04" .. "68656c6c6f"
local stream_data = hex2bin(stream_hex)
frame, offset = frames.parse_frame(stream_data, 1)
if frame and frame.type == 0x08 and frame.name == "STREAM" then
  print("✓ STREAM frame parsed correctly")
  print("  Stream ID: " .. tostring(frame.id))
  print("  Offset: " .. tostring(frame.offset))
  print("  Length: " .. tostring(frame.length))
  print("  Data: " .. tostring(frame.data))
  print("  FIN: " .. tostring(frame.fin))
else
  print("✗ STREAM frame parsing failed")
end
print("")
print("=== Multiple Frame Parsing ===")
local multi_hex = "00" .. "01" .. crypto_hex
local multi_data = hex2bin(multi_hex)
local frames_found = { }
for frame in frames.iter_frames(multi_data) do
  frames_found[#frames_found + 1] = frame
  print("Found " .. tostring(frame.name) .. " frame (type " .. tostring(string.format("0x%02x", frame.type)) .. ")")
end
if #frames_found == 3 then
  print("✓ Parsed " .. tostring(#frames_found) .. " frames correctly")
else
  print("✗ Expected 3 frames, got " .. tostring(#frames_found))
end
print("")
print("=== Frame Validation ===")
local valid, msg = frames.validate_frames(multi_data)
if valid then
  print("✓ Frame validation passed: " .. tostring(msg))
else
  print("✗ Frame validation failed: " .. tostring(msg))
end
print("")
print("=== Frame Types Reference ===")
print("Supported frame types:")
for code, name in pairs(frames.frame_types) do
  if type(code) == "number" then
    print("  0x" .. tostring(string.format("%02x", code)) .. ": " .. tostring(name))
  end
end
print("")
return print("=== Frame Parsing Tests Complete ===")
