#!/usr/bin/env moon

--- Simple PCAP debug - Focus on block parsing
unpack: su = string

print "=== Simple PCAPNG Debug ==="

file = io.open "quic.pcapng", "rb"
data = file\read "*all"
file\close!

print "File size: #{#data} bytes"

offset = 1
block_count = 0

while offset <= #data and block_count < 20
  break if offset + 8 > #data

  -- Read block type (try little-endian based on hexdump)
  block_type = su "<I4", data, offset
  block_len = su "<I4", data, offset + 4

  print "Block #{block_count + 1} at offset #{offset}:"
  print "  Type: 0x#{string.format "%08x", block_type}"
  print "  Length: #{block_len}"

  -- Identify block types
  switch block_type
    when 0x0A0D0D0A
      print "  -> Section Header Block (SHB)"
    when 0x00000001
      print "  -> Interface Description Block (IDB)"
    when 0x00000006
      print "  -> Enhanced Packet Block (EPB)"
      -- For EPB, show first few bytes of packet data
      if offset + 28 + 20 <= #data
        packet_start = offset + 28
        packet_preview = ""
        for i = 0, 19
          byte_val = su "B", data, packet_start + i
          packet_preview ..= string.format "%02x ", byte_val
        print "  -> Packet preview: #{packet_preview}"
    else
      print "  -> Unknown block type"

  break if block_len <= 0 or block_len > #data - offset + 1

  offset += block_len
  block_count += 1
  print ""

print "Processed #{block_count} blocks"

-- Now let's try to manually parse one EPB to see what's happening
print "\n=== Manual EPB Analysis ==="
epb_offset = nil

-- Find first EPB block
offset = 1
while offset <= #data
  break if offset + 8 > #data

  block_type = su "<I4", data, offset
  block_len = su "<I4", data, offset + 4

  if block_type == 0x00000006  -- EPB
    epb_offset = offset
    print "Found EPB at offset #{offset}"
    break

  offset += block_len

if epb_offset
  -- Parse EPB manually
  block_type, block_len, interface_id, ts_high, ts_low, captured_len, original_len = su "<I4I4I4I4I4I4I4", data, epb_offset

  print "EPB Details:"
  print "  Block type: 0x#{string.format "%08x", block_type}"
  print "  Block length: #{block_len}"
  print "  Interface ID: #{interface_id}"
  print "  Timestamp high: #{ts_high}"
  print "  Timestamp low: #{ts_low}"
  print "  Captured length: #{captured_len}"
  print "  Original length: #{original_len}"

  -- Extract packet data
  packet_start = epb_offset + 28
  print "  Packet data starts at offset #{packet_start}"

  if packet_start + captured_len <= #data
    print "  Packet data is within file bounds"
    -- Show first 32 bytes of packet
    packet_hex = ""
    for i = 0, math.min(31, captured_len - 1)
      byte_val = su "B", data, packet_start + i
      packet_hex ..= string.format "%02x", byte_val
      packet_hex ..= " " if (i + 1) % 8 == 0
    print "  First 32 bytes: #{packet_hex}"
  else
    print "  ERROR: Packet data extends beyond file!"
else
  print "No EPB blocks found"
