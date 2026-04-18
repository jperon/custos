#!/usr/bin/env moon

--- Working PCAP test based on debug results
-- This implements a working PCAP parser based on our debug findings

:bin2hex = require "ipparse.init"
unpack: su = string

print "=== Working PCAP Test ==="

-- Parse packets manually using what we learned
file = io.open "quic.pcapng", "rb"
data = file\read "*all"
file\close!

print "File size: #{#data} bytes"

-- We know from debug:
-- - Block 1: SHB at offset 1, length 128
-- - Block 2: IDB at offset 129, length 100
-- - Blocks 3-14: EPB blocks, each length 1328, containing packets

packets = {}
offset = 1

-- Skip SHB
offset = 129  -- Start at IDB

-- Skip IDB
offset = 229  -- Start at first EPB

-- Parse all EPB blocks (we know there are 12-14 of them)
while offset <= #data
  if offset + 8 > #data
    break

  block_type = su "<I4", data, offset
  block_len = su "<I4", data, offset + 4

  if block_type != 0x00000006  -- Not EPB
    print "Found non-EPB block at offset #{offset}, type: 0x#{string.format "%08x", block_type}"
    break

  -- Parse EPB
  block_type, block_len, interface_id, ts_high, ts_low, captured_len, original_len = su "<I4I4I4I4I4I4I4", data, offset

  -- Extract packet data
  packet_start = offset + 28
  packet_data = data\sub packet_start, packet_start + captured_len - 1

  packet = {
    packet_num: #packets + 1
    :interface_id, :ts_high, :ts_low, :captured_len, :original_len
    :packet_data
    timestamp: (ts_high << 32) + ts_low
  }

  packets[#packets + 1] = packet
  print "Parsed packet #{#packets}, size #{captured_len} bytes"

  offset += block_len

print "Total packets parsed: #{#packets}"
print ""

-- Now try to parse QUIC from these packets
eth = require "ipparse.l2.ethernet"
ip = require "ipparse.l3.ip"
udp = require "ipparse.l4.udp"
quic = require "ipparse.l4.quic"

quic_packets = {}

for i, packet in ipairs packets
  print "=== Analyzing Packet #{i} ==="

  -- Show first 64 bytes
  hex_preview = bin2hex(packet.packet_data\sub 1, math.min(64, #packet.packet_data))
  print "Raw data: #{hex_preview}"

  -- Parse Ethernet
  eth_frame, l3_offset = eth.parse packet.packet_data
  unless eth_frame
    print "Failed to parse Ethernet frame"
    continue

  print "Ethernet: #{eth.proto[eth_frame.protocol] or string.format "0x%04x", eth_frame.protocol}"

  -- Parse IP
  ip_pkt, l4_offset = ip.parse packet.packet_data, l3_offset, eth_frame.protocol
  unless ip_pkt
    print "Failed to parse IP packet"
    continue

  src_ip = ip.ip2s ip_pkt.src
  dst_ip = ip.ip2s ip_pkt.dst
  print "IP: #{src_ip} -> #{dst_ip}, protocol #{ip_pkt.protocol}"

  unless ip_pkt.protocol == ip.proto.UDP
    print "Not UDP packet"
    continue

  -- Parse UDP
  udp_dgram, l7_offset = udp.parse packet.packet_data, l4_offset
  unless udp_dgram
    print "Failed to parse UDP datagram"
    continue

  print "UDP: #{udp_dgram.spt} -> #{udp_dgram.dpt}"

  -- Check if this looks like QUIC (port 443)
  unless udp_dgram.dpt == 443 or udp_dgram.spt == 443
    print "Not on QUIC port 443"
    continue

  -- Try to parse QUIC header
  print "Attempting QUIC parsing at offset #{l7_offset}..."
  quic_data = packet.packet_data\sub l7_offset
  print "QUIC data (first 32 bytes): #{bin2hex quic_data\sub(1, math.min(32, #quic_data))}"

  quic_pkt, _ = quic.parse packet.packet_data, l7_offset
  if quic_pkt
    print "✓ QUIC header parsed successfully!"

    if quic_pkt.long_header
      dcid = bin2hex quic_pkt.dst_connection_id
      scid = bin2hex quic_pkt.src_connection_id or ""
      print "  Long header - Version: 0x#{string.format "%08x", quic_pkt.version}"
      print "  DCID: #{dcid}"
      print "  SCID: #{scid}"

      quic_packet = {
        packet_num: i
        :eth_frame, :ip_pkt, :udp_dgram, :quic_pkt
        raw_data: packet.packet_data
        quic_offset: l7_offset
      }
      quic_packets[#quic_packets + 1] = quic_packet
    else
      dcid = bin2hex quic_pkt.dst_connection_id
      print "  Short header - DCID: #{dcid}"
  else
    print "✗ Failed to parse QUIC header"

  print ""

print "=== QUIC Summary ==="
print "Total QUIC packets found: #{#quic_packets}"

expected_dcid = "133a971cdef32a97"
expected_scid = "fb0a4d"
matching_packets = 0

for pkt in *quic_packets
  dcid = bin2hex pkt.quic_pkt.dst_connection_id
  scid = bin2hex pkt.quic_pkt.src_connection_id or ""

  if dcid == expected_dcid and scid == expected_scid
    matching_packets += 1

print "Packets matching expected connection IDs: #{matching_packets}"
print "Expected DCID: #{expected_dcid}"
print "Expected SCID: #{expected_scid}"

if matching_packets > 0
  print "✓ SUCCESS: Found QUIC packets with expected connection IDs!"
else
  print "⚠ No packets match expected connection IDs"
