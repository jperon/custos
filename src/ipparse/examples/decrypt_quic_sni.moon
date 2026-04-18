#!/usr/bin/env moon

--- Decrypt SNI from QUIC packets in quic.pcapng
-- This script uses the ipparse API to decrypt QUIC packets and extract the SNI.

pcap = require "ipparse.lib.pcap"
:bin2hex = require "ipparse.init"
quic_decrypt = require "ipparse.l4.quic.decrypt"
quic_l7 = require "ipparse.l7.quic"

print "🔍 Decrypting SNI from QUIC packets in quic.pcapng"
print ""

-- Path to the PCAP file
pcap_file = "quic.pcapng"

-- QUIC connection ID to filter
connection_id = "133a971cdef32a97"

-- Read packets from the PCAP file
-- Check if the file exists
file = io.open pcap_file, "rb"
if file
  raw_data = file\read "*all"
  print "File size: #{#raw_data} bytes"
  print "File hex preview: #{bin2hex raw_data\sub(1, math.min(64, #raw_data))}"
  file\close!
if not file
  error "❌ File not found: #{pcap_file}"
else
  print "✅ File found: #{pcap_file}"
  file\close!

-- Parse the PCAPNG file
packets = pcap.parse_pcapng pcap_file
print "Parsed #{#packets} packets from #{pcap_file}"
print "Loaded #{#packets} packets from #{pcap_file}"

-- Filter packets by connection ID
filtered_packets = {}
for i, packet in ipairs(packets)
  print "Packet #{i}: Timestamp=#{packet.timestamp}, Length=#{#packet.packet_data}"
  if packet.connection_id
    print "  Connection ID: #{packet.connection_id}"
  else
    print "  ❌ No connection ID found in packet"
  if packet.connection_id == connection_id
    filtered_packets[#filtered_packets + 1] = packet

print "Filtered #{#filtered_packets} packets for connection ID #{connection_id}"

-- Decrypt the packets
decryption_results = quic_decrypt.decrypt_quic_packets connection_id, filtered_packets

-- Collect all frames from successful decryptions
all_frames = {}
for result in *decryption_results
  if result.success
    for frame in *result.frames
      all_frames[#all_frames + 1] = frame

print "Collected #{#all_frames} frames from decrypted packets"

-- Parse the frames to extract SNI
l7_parser = quic_l7.QuicL7Parser()
sni = l7_parser\process_frames all_frames

if sni
  print "🎉 SUCCESS: Extracted SNI '#{sni}'"
else
  print "❌ FAILED: No SNI found in the packets"
