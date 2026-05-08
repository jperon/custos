--
-- SPDX-FileCopyrightText: (c) 2024-2025 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- PCAP/PCAPNG File Parsing Module
-- This module provides utilities for parsing PCAP and PCAPNG files to extract network packets.
-- It supports both the original PCAP format and the newer PCAPNG format.
--
-- ### Features
-- - Parse PCAPNG Section Header Blocks (SHB)
-- - Parse Interface Description Blocks (IDB)
-- - Parse Enhanced Packet Blocks (EPB)
-- - Extract raw packet data with timestamps
-- - Support for different link layer types (Ethernet, Raw IP)
--
-- ### PCAPNG Block Structure
-- ```
-- Block {
--   block_type (32): Type of block (SHB=0x0A0D0D0A, IDB=0x00000001, EPB=0x00000006)
--   block_total_length (32): Total length of block including headers
--   block_data (variable): Block-specific data
--   block_total_length (32): Repeated at end for validation
-- }
-- ```
--
-- References:
-- - RFC 2838: Pcap File Format
-- - PCAPNG Specification: https://github.com/pcapng/pcapng
--
-- @module lib.pcap

{:lshift} = require"ipparse.lib.bit_compat"

unpack: su = require "ipparse.lib.pack_compat"
:bin2hex, :hex2bin = require "ipparse.init"

--- PCAPNG Block Types
-- Mapping of block type codes to their names
block_types = {
  [0x0A0D0D0A]: "SHB"    -- Section Header Block
  [0x00000001]: "IDB"    -- Interface Description Block
  [0x00000006]: "EPB"    -- Enhanced Packet Block
  [0x00000002]: "PB"     -- Packet Block (deprecated)
  [0x00000003]: "SPB"    -- Simple Packet Block
  [0x00000004]: "NRB"    -- Name Resolution Block
  [0x00000005]: "ISB"    -- Interface Statistics Block
}

--- Link Layer Types (from pcap specification)
link_types = {
  [1]: "ETHERNET"        -- Ethernet (10Mb, 100Mb, 1000Mb, and up)
  [101]: "RAW_IP4"       -- Raw IP; the packet begins with an IPv4 header
  [228]: "RAW_IP6"       -- Raw IP; the packet begins with an IPv6 header
  [12]: "RAW_IP"         -- Raw IP; begins with IP header (version determines IPv4/IPv6)
}

--- Parses a PCAPNG Section Header Block (SHB)
-- @tparam string data The binary data containing the SHB
-- @tparam number offset Starting offset in the data
-- @treturn table Parsed SHB structure
-- @treturn number Next offset after the block
parse_shb = (data, offset) ->
  -- Always try little-endian first since that's what our file uses
  block_type, block_len, byte_order_magic = su "<I4I4I4", data, offset

  -- Check byte order magic (0x1A2B3C4D for big-endian, 0x4D3C2B1A for little-endian)
  endian = byte_order_magic == 0x1A2B3C4D and ">" or "<"

  -- Re-parse with correct endianness for the full structure
  local major_version, minor_version, section_length
  if endian == ">"
    block_type, block_len, byte_order_magic, major_version, minor_version = su ">I4I4I4I2I2", data, offset
    section_length = su ">I8", data, offset + 16
  else
    block_type, block_len, byte_order_magic, major_version, minor_version = su "<I4I4I4I2I2", data, offset
    section_length = su "<I8", data, offset + 16

  shb = {
    :block_type, :block_len, :byte_order_magic, :major_version, :minor_version, :section_length, :endian
  }

  shb, offset + block_len

--- Parses a PCAPNG Interface Description Block (IDB)
-- @tparam string data The binary data containing the IDB
-- @tparam number offset Starting offset in the data
-- @tparam string endian Byte order (">" for big-endian, "<" for little-endian)
-- @treturn table Parsed IDB structure
-- @treturn number Next offset after the block
parse_idb = (data, offset, endian) ->
  -- IDB format: block_type(4) + block_len(4) + linktype(2) + reserved(2) + snaplen(4) + options + block_len(4)
  block_type, block_len, linktype, reserved, snaplen = su "#{endian}I4I4I2I2I4", data, offset

  idb = {
    :block_type, :block_len, :linktype, :reserved, :snaplen
    linktype_name: link_types[linktype] or "UNKNOWN"
  }

  idb, offset + block_len

--- Parses a PCAPNG Enhanced Packet Block (EPB)
-- @tparam string data The binary data containing the EPB
-- @tparam number offset Starting offset in the data
-- @tparam string endian Byte order (">" for big-endian, "<" for little-endian)
-- @treturn table Parsed EPB structure with packet data
-- @treturn number Next offset after the block
parse_epb = (data, offset, endian) ->
  -- EPB format: block_type(4) + block_len(4) + interface_id(4) + timestamp_high(4) + timestamp_low(4) + captured_len(4) + original_len(4) + packet_data + options + block_len(4)
  block_type, block_len, interface_id, timestamp_high, timestamp_low, captured_len, original_len = su "#{endian}I4I4I4I4I4I4I4", data, offset

  -- Extract packet data
  packet_start = offset + 28  -- After all the headers
  packet_data = data\sub packet_start, packet_start + captured_len - 1

  -- Calculate timestamp (microseconds since epoch, split into high/low 32-bit words)
  timestamp = lshift(timestamp_high, 32) + timestamp_low

  epb = {
    :block_type, :block_len, :interface_id, :timestamp_high, :timestamp_low, :timestamp
    :captured_len, :original_len, :packet_data
  }

  epb, offset + block_len

--- Parses a PCAPNG file and extracts all packets
-- @tparam string filename Path to the PCAPNG file
-- @treturn table Array of parsed packets with metadata
parse_pcapng = (filename) ->
  -- Read entire file into memory
  file = io.open filename, "rb"
  unless file
    error "Could not open file: #{filename}"

  data = file\read "*all"
  file\close!

  packets = {}
  interfaces = {}
  offset = 1
  endian = ">"  -- Default big-endian, will be set by SHB

  while offset <= #data
    -- Read block type
    if offset + 8 > #data
      break

    -- Try reading with current endianness first
    block_type = su "#{endian}I4", data, offset
    block_name = block_types[block_type] or "UNKNOWN"

    -- If we don't recognize the block, and we haven't set endianness yet, try the other endianness
    if block_name == "UNKNOWN" and endian == ">"
      block_type = su "<I4", data, offset
      block_name = block_types[block_type] or "UNKNOWN"

    switch block_name
      when "SHB"
        shb, offset = parse_shb data, offset
        endian = shb.endian
        print "Found Section Header Block - endian: #{endian}"

      when "IDB"
        idb, offset = parse_idb data, offset, endian
        interfaces[#interfaces + 1] = idb
        print "Found Interface Description Block - linktype: #{idb.linktype_name}"

      when "EPB"
        epb, offset = parse_epb data, offset, endian
        -- Add interface info to packet
        epb.interface = interfaces[epb.interface_id + 1]  -- IDs are 0-based
        packets[#packets + 1] = epb
        print "Found Enhanced Packet Block - packet #{#packets}, len: #{epb.captured_len}, timestamp: #{epb.timestamp}"

      else
        -- Skip unknown blocks
        if offset + 8 <= #data
          block_len = su "#{endian}I4", data, offset + 4
          if block_len <= 0 or block_len > #data or offset + block_len > #data
            print "Invalid block length #{block_len} at offset #{offset}, stopping"
            break
          offset += block_len
          print "Skipping unknown block type: 0x#{string.format "%08x", block_type}, len: #{block_len}"
        else
          break

  print "Parsed #{#packets} packets from #{filename}"
  packets

--- Filters packets to find QUIC packets on standard ports
-- @tparam table packets Array of parsed packets
-- @treturn table Array of QUIC packets with parsed headers
filter_quic_packets = (packets) ->
  eth = require "ipparse.l2.ethernet"
  ip = require "ipparse.l3.ip"
  udp = require "ipparse.l4.udp"
  quic = require "ipparse.l4.quic"

  quic_packets = {}

  for i, packet in ipairs packets
    -- Parse Ethernet frame
    eth_frame, l3_offset = eth.parse packet.packet_data
    continue unless eth_frame

    -- Parse IP packet (IPv4 or IPv6)
    ip_pkt, l4_offset = ip.parse packet.packet_data, l3_offset, eth_frame.protocol
    continue unless ip_pkt and ip_pkt.protocol == ip.proto.UDP

    -- Parse UDP datagram
    udp_dgram, l7_offset = udp.parse packet.packet_data, l4_offset
    continue unless udp_dgram

    -- Filter for QUIC ports (443, 80, 8443, etc.)
    quic_ports = {[443]: true, [80]: true, [8443]: true, [4433]: true}
    is_quic = quic_ports[udp_dgram.spt] or quic_ports[udp_dgram.dpt]
    continue unless is_quic

    -- Parse QUIC header
    quic_pkt, _ = quic.parse packet.packet_data, l7_offset
    if quic_pkt
      quic_packet = {
        packet_num: i
        timestamp: packet.timestamp
        :eth_frame, :ip_pkt, :udp_dgram, :quic_pkt
        raw_data: packet.packet_data
        quic_offset: l7_offset
      }
      quic_packets[#quic_packets + 1] = quic_packet

      -- Print packet summary
      src_ip = ip.ip2s ip_pkt.src
      dst_ip = ip.ip2s ip_pkt.dst
      print "QUIC Packet #{i}: #{src_ip}:#{udp_dgram.spt} -> #{dst_ip}:#{udp_dgram.dpt}"

      if quic_pkt.long_header
        dcid = bin2hex quic_pkt.dst_connection_id
        scid = bin2hex quic_pkt.src_connection_id
        print "  Long Header - Version: 0x#{string.format "%08x", quic_pkt.version}, DCID: #{dcid}, SCID: #{scid}"
      else
        dcid = bin2hex quic_pkt.dst_connection_id
        print "  Short Header - DCID: #{dcid}"

  print "Found #{#quic_packets} QUIC packets"
  quic_packets

--- Main function to parse QUIC packets from a PCAPNG file
-- @tparam string filename Path to the PCAPNG file
-- @treturn table Array of QUIC packets with full parsing
parse_quic_from_pcapng = (filename="quic.pcapng") ->
  packets = parse_pcapng filename
  filter_quic_packets packets

:parse_pcapng, :parse_quic_from_pcapng, :filter_quic_packets, :block_types, :link_types
