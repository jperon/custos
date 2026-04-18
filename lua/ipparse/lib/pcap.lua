local lshift
lshift = require("ipparse.lib.bit_compat").lshift
local su
su = require("ipparse.lib.pack_compat").unpack
local bin2hex, hex2bin
do
  local _obj_0 = require("ipparse.init")
  bin2hex, hex2bin = _obj_0.bin2hex, _obj_0.hex2bin
end
local block_types = {
  [0x0A0D0D0A] = "SHB",
  [0x00000001] = "IDB",
  [0x00000006] = "EPB",
  [0x00000002] = "PB",
  [0x00000003] = "SPB",
  [0x00000004] = "NRB",
  [0x00000005] = "ISB"
}
local link_types = {
  [1] = "ETHERNET",
  [101] = "RAW_IP4",
  [228] = "RAW_IP6",
  [12] = "RAW_IP"
}
local parse_shb
parse_shb = function(data, offset)
  local block_type, block_len, byte_order_magic = su("<I4I4I4", data, offset)
  local endian = byte_order_magic == 0x1A2B3C4D and ">" or "<"
  local major_version, minor_version, section_length
  if endian == ">" then
    block_type, block_len, byte_order_magic, major_version, minor_version = su(">I4I4I4I2I2", data, offset)
    section_length = su(">I8", data, offset + 16)
  else
    block_type, block_len, byte_order_magic, major_version, minor_version = su("<I4I4I4I2I2", data, offset)
    section_length = su("<I8", data, offset + 16)
  end
  local shb = {
    block_type = block_type,
    block_len = block_len,
    byte_order_magic = byte_order_magic,
    major_version = major_version,
    minor_version = minor_version,
    section_length = section_length,
    endian = endian
  }
  return shb, offset + block_len
end
local parse_idb
parse_idb = function(data, offset, endian)
  local block_type, block_len, linktype, reserved, snaplen = su(tostring(endian) .. "I4I4I2I2I4", data, offset)
  local idb = {
    block_type = block_type,
    block_len = block_len,
    linktype = linktype,
    reserved = reserved,
    snaplen = snaplen,
    linktype_name = link_types[linktype] or "UNKNOWN"
  }
  return idb, offset + block_len
end
local parse_epb
parse_epb = function(data, offset, endian)
  local block_type, block_len, interface_id, timestamp_high, timestamp_low, captured_len, original_len = su(tostring(endian) .. "I4I4I4I4I4I4I4", data, offset)
  local packet_start = offset + 28
  local packet_data = data:sub(packet_start, packet_start + captured_len - 1)
  local timestamp = lshift(timestamp_high, 32) + timestamp_low
  local epb = {
    block_type = block_type,
    block_len = block_len,
    interface_id = interface_id,
    timestamp_high = timestamp_high,
    timestamp_low = timestamp_low,
    timestamp = timestamp,
    captured_len = captured_len,
    original_len = original_len,
    packet_data = packet_data
  }
  return epb, offset + block_len
end
local parse_pcapng
parse_pcapng = function(filename)
  local file = io.open(filename, "rb")
  if not (file) then
    error("Could not open file: " .. tostring(filename))
  end
  local data = file:read("*all")
  file:close()
  local packets = { }
  local interfaces = { }
  local offset = 1
  local endian = ">"
  while offset <= #data do
    if offset + 8 > #data then
      break
    end
    local block_type = su(tostring(endian) .. "I4", data, offset)
    local block_name = block_types[block_type] or "UNKNOWN"
    if block_name == "UNKNOWN" and endian == ">" then
      block_type = su("<I4", data, offset)
      block_name = block_types[block_type] or "UNKNOWN"
    end
    local _exp_0 = block_name
    if "SHB" == _exp_0 then
      local shb
      shb, offset = parse_shb(data, offset)
      endian = shb.endian
      print("Found Section Header Block - endian: " .. tostring(endian))
    elseif "IDB" == _exp_0 then
      local idb
      idb, offset = parse_idb(data, offset, endian)
      interfaces[#interfaces + 1] = idb
      print("Found Interface Description Block - linktype: " .. tostring(idb.linktype_name))
    elseif "EPB" == _exp_0 then
      local epb
      epb, offset = parse_epb(data, offset, endian)
      epb.interface = interfaces[epb.interface_id + 1]
      packets[#packets + 1] = epb
      print("Found Enhanced Packet Block - packet " .. tostring(#packets) .. ", len: " .. tostring(epb.captured_len) .. ", timestamp: " .. tostring(epb.timestamp))
    else
      if offset + 8 <= #data then
        local block_len = su(tostring(endian) .. "I4", data, offset + 4)
        if block_len <= 0 or block_len > #data or offset + block_len > #data then
          print("Invalid block length " .. tostring(block_len) .. " at offset " .. tostring(offset) .. ", stopping")
          break
        end
        offset = offset + block_len
        print("Skipping unknown block type: 0x" .. tostring(string.format("%08x", block_type)) .. ", len: " .. tostring(block_len))
      else
        break
      end
    end
  end
  print("Parsed " .. tostring(#packets) .. " packets from " .. tostring(filename))
  return packets
end
local filter_quic_packets
filter_quic_packets = function(packets)
  local eth = require("ipparse.l2.ethernet")
  local ip = require("ipparse.l3.ip")
  local udp = require("ipparse.l4.udp")
  local quic = require("ipparse.l4.quic")
  local quic_packets = { }
  for i, packet in ipairs(packets) do
    local _continue_0 = false
    repeat
      local eth_frame, l3_offset = eth.parse(packet.packet_data)
      if not (eth_frame) then
        _continue_0 = true
        break
      end
      local ip_pkt, l4_offset = ip.parse(packet.packet_data, l3_offset, eth_frame.protocol)
      if not (ip_pkt and ip_pkt.protocol == ip.proto.UDP) then
        _continue_0 = true
        break
      end
      local udp_dgram, l7_offset = udp.parse(packet.packet_data, l4_offset)
      if not (udp_dgram) then
        _continue_0 = true
        break
      end
      local quic_ports = {
        [443] = true,
        [80] = true,
        [8443] = true,
        [4433] = true
      }
      local is_quic = quic_ports[udp_dgram.spt] or quic_ports[udp_dgram.dpt]
      if not (is_quic) then
        _continue_0 = true
        break
      end
      local quic_pkt, _ = quic.parse(packet.packet_data, l7_offset)
      if quic_pkt then
        local quic_packet = {
          packet_num = i,
          timestamp = packet.timestamp,
          eth_frame = eth_frame,
          ip_pkt = ip_pkt,
          udp_dgram = udp_dgram,
          quic_pkt = quic_pkt,
          raw_data = packet.packet_data,
          quic_offset = l7_offset
        }
        quic_packets[#quic_packets + 1] = quic_packet
        local src_ip = ip.ip2s(ip_pkt.src)
        local dst_ip = ip.ip2s(ip_pkt.dst)
        print("QUIC Packet " .. tostring(i) .. ": " .. tostring(src_ip) .. ":" .. tostring(udp_dgram.spt) .. " -> " .. tostring(dst_ip) .. ":" .. tostring(udp_dgram.dpt))
        if quic_pkt.long_header then
          local dcid = bin2hex(quic_pkt.dst_connection_id)
          local scid = bin2hex(quic_pkt.src_connection_id)
          print("  Long Header - Version: 0x" .. tostring(string.format("%08x", quic_pkt.version)) .. ", DCID: " .. tostring(dcid) .. ", SCID: " .. tostring(scid))
        else
          local dcid = bin2hex(quic_pkt.dst_connection_id)
          print("  Short Header - DCID: " .. tostring(dcid))
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  print("Found " .. tostring(#quic_packets) .. " QUIC packets")
  return quic_packets
end
local parse_quic_from_pcapng
parse_quic_from_pcapng = function(filename)
  if filename == nil then
    filename = "quic.pcapng"
  end
  local packets = parse_pcapng(filename)
  return filter_quic_packets(packets)
end
return {
  parse_pcapng = parse_pcapng,
  parse_quic_from_pcapng = parse_quic_from_pcapng,
  filter_quic_packets = filter_quic_packets,
  block_types = block_types,
  link_types = link_types
}
