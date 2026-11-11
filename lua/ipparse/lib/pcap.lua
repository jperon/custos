local unpack
unpack = require("ipparse.lib.pack_compat").unpack
local su = unpack
local bin2hex, need_bytes
do
  local _obj_0 = require("ipparse.init")
  bin2hex, need_bytes = _obj_0.bin2hex, _obj_0.need_bytes
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
local M = {
  verbose = false
}
local log
log = function(msg)
  if M.verbose then
    return print(msg)
  end
end
local parse_shb
parse_shb = function(data, offset)
  if not (need_bytes(data, offset, 28)) then
    return nil, offset, "insufficient data for SHB header"
  end
  local endian = su(">I4", data, offset + 8) == 0x1A2B3C4D and ">" or "<"
  local block_type = su(tostring(endian) .. "I4", data, offset)
  local block_len = su(tostring(endian) .. "I4", data, offset + 4)
  local byte_order_magic = su(tostring(endian) .. "I4", data, offset + 8)
  local major_version = su(tostring(endian) .. "I2", data, offset + 12)
  local minor_version = su(tostring(endian) .. "I2", data, offset + 14)
  local section_length = su(tostring(endian) .. "I8", data, offset + 16)
  log("parse_shb: endian=" .. tostring(endian) .. ", block_type=" .. tostring(block_type) .. ", block_len=" .. tostring(block_len))
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
  if not (need_bytes(data, offset, 16)) then
    return nil, offset, "insufficient data for IDB header"
  end
  local block_type, block_len, linktype, reserved, snaplen = su(tostring(endian) .. "I4I4I2I2I4", data, offset)
  local idb = {
    block_type = block_type,
    block_len = block_len,
    linktype = linktype,
    reserved = reserved,
    snaplen = snaplen,
    endian = endian,
    linktype_name = link_types[linktype] or "UNKNOWN"
  }
  return idb, offset + block_len
end
local parse_epb
parse_epb = function(data, offset, endian)
  if not (need_bytes(data, offset, 28)) then
    return nil, offset, "insufficient data for EPB header"
  end
  local block_type, block_len, interface_id, timestamp_high, timestamp_low, captured_len, original_len = su(tostring(endian) .. "I4I4I4I4I4I4I4", data, offset)
  if 28 + captured_len + 4 > block_len then
    return nil, offset + block_len
  end
  local packet_start = offset + 28
  local packet_data = data:sub(packet_start, packet_start + captured_len - 1)
  local timestamp = timestamp_high * 4294967296 + timestamp_low
  local epb = {
    block_type = block_type,
    block_len = block_len,
    interface_id = interface_id,
    timestamp_hi = timestamp_high,
    timestamp_lo = timestamp_low,
    timestamp = timestamp,
    captured_len = captured_len,
    original_len = original_len,
    packet_data = packet_data,
    endian = endian
  }
  return epb, offset + block_len
end
local parse_pcapng_data
parse_pcapng_data = function(data)
  local packets = { }
  local all_blocks = { }
  local interfaces = { }
  local shb = nil
  local offset = 1
  local endian = ">"
  while offset <= #data do
    local _continue_0 = false
    repeat
      if offset + 8 > #data then
        log("End of data at offset " .. tostring(offset))
        break
      end
      local block_type = su(tostring(endian) .. "I4", data, offset)
      local block_name = block_types[block_type] or "UNKNOWN"
      log("Offset " .. tostring(offset) .. ": block_type=0x" .. tostring(string.format("%08x", block_type)) .. " (" .. tostring(block_name) .. "), endian=" .. tostring(endian))
      if block_name == "UNKNOWN" and endian == ">" then
        block_type = su("<I4", data, offset)
        block_name = block_types[block_type] or "UNKNOWN"
        log("Trying little-endian: block_type=0x" .. tostring(string.format("%08x", block_type)) .. " (" .. tostring(block_name) .. ")")
      end
      if block_name == "SHB" then
        endian = su(">I4", data, offset + 8) == 0x1A2B3C4D and ">" or "<"
        block_type = su(tostring(endian) .. "I4", data, offset)
        log("Section Header Block byte-order magic, endian: " .. tostring(endian))
      end
      local block_len = su(tostring(endian) .. "I4", data, offset + 4)
      if block_len < 12 or block_len % 4 ~= 0 or offset + block_len - 1 > #data then
        log("Invalid block length " .. tostring(block_len) .. " at offset " .. tostring(offset) .. ", stopping")
        break
      end
      local _exp_0 = block_name
      if "SHB" == _exp_0 then
        local shb_data
        shb_data, offset = parse_shb(data, offset)
        if not (shb_data) then
          break
        end
        all_blocks[#all_blocks + 1] = {
          type = "SHB",
          data = shb_data
        }
        shb = shb_data
        endian = shb.endian
        log("Found Section Header Block - endian: " .. tostring(endian))
      elseif "IDB" == _exp_0 then
        local idb, next_offset = parse_idb(data, offset, endian)
        if not (idb) then
          offset = offset + block_len
          _continue_0 = true
          break
        end
        offset = next_offset
        all_blocks[#all_blocks + 1] = {
          type = "IDB",
          data = idb
        }
        interfaces[#interfaces + 1] = idb
        log("Found Interface Description Block - linktype: " .. tostring(idb.linktype_name))
      elseif "EPB" == _exp_0 then
        local epb
        epb, offset = parse_epb(data, offset, endian)
        if epb then
          all_blocks[#all_blocks + 1] = {
            type = "EPB",
            data = epb
          }
          epb.interface = interfaces[epb.interface_id + 1]
          packets[#packets + 1] = epb
          log("Found Enhanced Packet Block - packet " .. tostring(#packets) .. ", len: " .. tostring(epb.captured_len) .. ", timestamp: " .. tostring(epb.timestamp))
        else
          log("Skipping invalid EPB at offset " .. tostring(offset))
        end
      else
        local raw_data = data:sub(offset, offset + block_len - 1)
        all_blocks[#all_blocks + 1] = {
          type = "UNKNOWN",
          raw_data = raw_data,
          block_type = block_type
        }
        log("Found unknown block type: 0x" .. tostring(string.format("%08x", block_type)) .. ", len: " .. tostring(block_len) .. " at offset " .. tostring(offset))
        offset = offset + block_len
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  log("Parsed " .. tostring(#packets) .. " packets")
  return packets, all_blocks
end
local parse_pcapng
parse_pcapng = function(filename)
  local file = io.open(filename, "rb")
  if not (file) then
    error("Could not open file: " .. tostring(filename))
  end
  local data = file:read("*all")
  file:close()
  return parse_pcapng_data(data)
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
        log("QUIC Packet " .. tostring(i) .. ": " .. tostring(src_ip) .. ":" .. tostring(udp_dgram.spt) .. " -> " .. tostring(dst_ip) .. ":" .. tostring(udp_dgram.dpt))
        if quic_pkt.long_header then
          local dcid = bin2hex(quic_pkt.dst_connection_id)
          local scid = bin2hex(quic_pkt.src_connection_id)
          log("  Long Header - Version: 0x" .. tostring(string.format("%08x", quic_pkt.version)) .. ", DCID: " .. tostring(dcid) .. ", SCID: " .. tostring(scid))
        else
          local dcid = bin2hex((quic_pkt.dst_connection_id or ""))
          log("  Short Header - DCID: " .. tostring(dcid))
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  log("Found " .. tostring(#quic_packets) .. " QUIC packets")
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
M.parse_pcapng = parse_pcapng
M.parse_pcapng_data = parse_pcapng_data
M.parse_quic_from_pcapng = parse_quic_from_pcapng
M.filter_quic_packets = filter_quic_packets
M.block_types = block_types
M.link_types = link_types
return M
