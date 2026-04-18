#!/usr/bin/env moon

--- Debug PCAP file structure
-- Simple script to examine the raw structure of quic.pcapng

:bin2hex, :hexdump = require "ipparse.init"
unpack: su = string

print "=== PCAPNG File Debug ==="

-- Read the file
file = io.open "quic.pcapng", "rb"
unless file
  print "Could not open quic.pcapng"
  os.exit 1

data = file\read "*all"
file\close!

print "File size: #{#data} bytes"
print ""

-- Show first 256 bytes as hex dump
print "=== First 256 bytes ==="
print hexdump data\sub(1, math.min(256, #data))
print ""

-- Parse blocks manually
offset = 1
block_count = 0

while offset <= #data and block_count < 10
  if offset + 8 > #data
    print "Not enough data for block header at offset #{offset}"
    break

  -- Read block type and length
  block_type, block_len = su "<I4I4", data, offset  -- Try little-endian first

  print "=== Block #{block_count + 1} at offset #{offset} ==="
  print "Block type: 0x#{string.format "%08x", block_type}"
  print "Block length: #{block_len}"

  -- Check if this looks like a known block type
  block_names = {
    [0x0A0D0D0A]: "SHB (Section Header Block)"
    [0x00000001]: "IDB (Interface Description Block)"
    [0x00000006]: "EPB (Enhanced Packet Block)"
    [0x00000002]: "PB (Packet Block)"
    [0x00000003]: "SPB (Simple Packet Block)"
  }

  if block_names[block_type]
    print "Recognized: #{block_names[block_type]}"
  else
    print "Unknown block type"

  -- Show raw block data (first 64 bytes)
  if offset + math.min(64, block_len) <= #data
    block_data = data\sub offset, offset + math.min(64, block_len) - 1
    print "Block data (first 64 bytes):"
    print hexdump block_data

  -- Try to validate block length
  if block_len <= 0 or block_len > #data
    print "Invalid block length: #{block_len}"
    break

  if offset + block_len > #data
    print "Block extends beyond file end"
    break

  print ""
  offset += block_len
  block_count += 1

print "Processed #{block_count} blocks"
print "Final offset: #{offset}, file size: #{#data}"
