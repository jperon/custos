#!/usr/bin/env moon

--- Simple Frame Test
-- Basic test for QUIC frame parsing

frames = require "ipparse.l4.quic.frames"
:bin2hex, :hex2bin = require "ipparse.init"

print "=== Simple Frame Test ==="

-- Test basic frame parsing
print "Testing PADDING frame..."
padding_data = hex2bin "00"
frame, offset = frames.parse_frame padding_data, 1

if frame
  print "✓ PADDING frame parsed: #{frame.name} (type #{string.format "0x%02x", frame.type})"
else
  print "✗ Failed to parse PADDING frame"

print "Testing PING frame..."
ping_data = hex2bin "01"
frame, offset = frames.parse_frame ping_data, 1

if frame
  print "✓ PING frame parsed: #{frame.name} (type #{string.format "0x%02x", frame.type})"
else
  print "✗ Failed to parse PING frame"

print "Testing CRYPTO frame..."
-- Type 0x06 + offset 0x00 + length 0x04 + data "test"
crypto_data = hex2bin "060004" .. bin2hex "test"
frame, offset = frames.parse_frame crypto_data, 1

if frame
  print "✓ CRYPTO frame parsed: #{frame.name}"
  print "  Offset: #{frame.offset}"
  print "  Length: #{frame.length}"
  print "  Data: #{frame.data}"
else
  print "✗ Failed to parse CRYPTO frame"

print "Frame parsing test complete!"
