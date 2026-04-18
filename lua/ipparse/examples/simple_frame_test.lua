local frames = require("ipparse.l4.quic.frames")
local bin2hex, hex2bin
do
  local _obj_0 = require("ipparse.init")
  bin2hex, hex2bin = _obj_0.bin2hex, _obj_0.hex2bin
end
print("=== Simple Frame Test ===")
print("Testing PADDING frame...")
local padding_data = hex2bin("00")
local frame, offset = frames.parse_frame(padding_data, 1)
if frame then
  print("✓ PADDING frame parsed: " .. tostring(frame.name) .. " (type " .. tostring(string.format("0x%02x", frame.type)) .. ")")
else
  print("✗ Failed to parse PADDING frame")
end
print("Testing PING frame...")
local ping_data = hex2bin("01")
frame, offset = frames.parse_frame(ping_data, 1)
if frame then
  print("✓ PING frame parsed: " .. tostring(frame.name) .. " (type " .. tostring(string.format("0x%02x", frame.type)) .. ")")
else
  print("✗ Failed to parse PING frame")
end
print("Testing CRYPTO frame...")
local crypto_data = hex2bin("060004" .. bin2hex("test"))
frame, offset = frames.parse_frame(crypto_data, 1)
if frame then
  print("✓ CRYPTO frame parsed: " .. tostring(frame.name))
  print("  Offset: " .. tostring(frame.offset))
  print("  Length: " .. tostring(frame.length))
  print("  Data: " .. tostring(frame.data))
else
  print("✗ Failed to parse CRYPTO frame")
end
return print("Frame parsing test complete!")
