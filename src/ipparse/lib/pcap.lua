local lshift
lshift = require("ipparse.lib.bit_compat").lshift
local unpack, pack
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  unpack, pack = _obj_0.unpack, _obj_0.pack
end
local su = unpack
local sp = pack
local bin2hex, hex2bin, need_bytes
do
  local _obj_0 = require("ipparse.init")
  bin2hex, hex2bin, need_bytes = _obj_0.bin2hex, _obj_0.hex2bin, _obj_0.need_bytes
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
  if not (need_bytes(data, offset, 12)) then
    return nil, offset, "insufficient data for SHB header"
  end
  local endian = nil
  local ok, byte_order_magic = pcall(su, ">I4", data, offset + 8)
  print("parse_shb: big-endian read ok=" .. tostring(ok) .. ", byte_order_magic=0x" .. tostring(string.format('%08x', byte_order_magic or 0)) .. ", numeric=" .. tostring(byte_order_magic))
  if ok then
    local hex_magic = string.format('%08x', byte_order_magic)
    print("parse_shb: hex_magic=" .. tostring(hex_magic))
    if hex_magic == '1a2b3c4d' then
      endian = ">"
    else
      endian = "<"
    end
  else
    ok, byte_order_magic = pcall(su, "<I4", data, offset + 8)
    print("parse_shb: little-endian read ok=" .. tostring(ok) .. ", byte_order_magic=0x" .. tostring(string.format('%08x', byte_order_magic or 0)) .. ", numeric=" .. tostring(byte_order_magic))
    if ok then
      local hex_magic = string.format('%08x', byte_order_magic)
      print("parse_shb: hex_magic=" .. tostring(hex_magic))
      if hex_magic == '1a2b3c4d' then
        endian = ">"
      else
        endian = "<"
      end
    else
      endian = "<"
    end
  end
  print("parse_shb: detected endian=" .. tostring(endian))
  print("parse_shb: data length=" .. tostring(#data) .. ", offset=" .. tostring(offset))
  local block_type, block_len, major_version, minor_version, section_length
  block_type, block_len, byte_order_magic, major_version, minor_version, section_length = nil
  if endian == ">" then
    print("parse_shb: parsing with big-endian")
    block_type = su(">I4", data, offset)
    print("parse_shb: after first su, block_type=" .. tostring(block_type))
    block_len = su(">I4", data, offset + 4)
    byte_order_magic = su(">I4", data, offset + 8)
    major_version = su(">I2", data, offset + 12)
    minor_version = su(">I2", data, offset + 14)
    section_length = su(">I8", data, offset + 16)
  else
    print("parse_shb: parsing with little-endian")
    print("parse_shb: calling su with format '<I4', data length " .. tostring(#data) .. ", offset " .. tostring(offset))
    block_type = su("<I4", data, offset)
    print("parse_shb: block_type su: ok=true, block_type=" .. tostring(block_type))
    block_len = su("<I4", data, offset + 4)
    print("parse_shb: block_len su: ok=true, block_len=" .. tostring(block_len))
    byte_order_magic = su("<I4", data, offset + 8)
    print("parse_shb: byte_order_magic su: ok=true, byte_order_magic=" .. tostring(byte_order_magic))
    major_version = su("<I2", data, offset + 12)
    print("parse_shb: major_version su: ok=true, major_version=" .. tostring(major_version))
    minor_version = su("<I2", data, offset + 14)
    print("parse_shb: minor_version su: ok=true, minor_version=" .. tostring(minor_version))
    section_length = su("<I8", data, offset + 16)
    print("parse_shb: section_length su: ok=true, section_length=" .. tostring(section_length))
  end
  print("parse_shb: block_type=" .. tostring(block_type) .. ", block_len=" .. tostring(block_len))
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
  local packet_start = offset + 28
  local packet_data = data:sub(packet_start, packet_start + captured_len - 1)
  local timestamp = lshift(timestamp_high, 32) + timestamp_low
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
local parse_pcapng
parse_pcapng = function(filename)
  local file = io.open(filename, "rb")
  if not (file) then
    error("Could not open file: " .. tostring(filename))
  end
  local data = file:read("*all")
  file:close()
  local packets = { }
  local all_blocks = { }
  local interfaces = { }
  local shb = nil
  local offset = 1
  local endian = ">"
  while offset <= #data do
    if offset + 8 > #data then
      print("End of data at offset " .. tostring(offset))
      break
    end
    local block_type = su(tostring(endian) .. "I4", data, offset)
    local block_name = block_types[block_type] or "UNKNOWN"
    print("Offset " .. tostring(offset) .. ": block_type=0x" .. tostring(string.format("%08x", block_type)) .. " (" .. tostring(block_name) .. "), endian=" .. tostring(endian))
    if block_name == "UNKNOWN" and endian == ">" then
      block_type = su("<I4", data, offset)
      block_name = block_types[block_type] or "UNKNOWN"
      print("Trying little-endian: block_type=0x" .. tostring(string.format("%08x", block_type)) .. " (" .. tostring(block_name) .. ")")
    end
    local _exp_0 = block_name
    if "SHB" == _exp_0 then
      local shb_data
      shb_data, offset = parse_shb(data, offset)
      all_blocks[#all_blocks + 1] = {
        type = "SHB",
        data = shb_data
      }
      shb = shb_data
      endian = shb.endian
      print("Found Section Header Block - endian: " .. tostring(endian))
    elseif "IDB" == _exp_0 then
      local idb
      idb, offset = parse_idb(data, offset, endian)
      all_blocks[#all_blocks + 1] = {
        type = "IDB",
        data = idb
      }
      interfaces[#interfaces + 1] = idb
      print("Found Interface Description Block - linktype: " .. tostring(idb.linktype_name))
    elseif "EPB" == _exp_0 then
      local epb
      epb, offset = parse_epb(data, offset, endian)
      all_blocks[#all_blocks + 1] = {
        type = "EPB",
        data = epb
      }
      epb.interface = interfaces[epb.interface_id + 1]
      packets[#packets + 1] = epb
      print("Found Enhanced Packet Block - packet " .. tostring(#packets) .. ", len: " .. tostring(epb.captured_len) .. ", timestamp: " .. tostring(epb.timestamp))
    else
      if offset + 8 <= #data then
        local block_len = su(tostring(endian) .. "I4", data, offset + 4)
        local raw_data = data:sub(offset, offset + block_len - 1)
        all_blocks[#all_blocks + 1] = {
          type = "UNKNOWN",
          raw_data = raw_data,
          block_type = block_type
        }
        print("Found unknown block type: 0x" .. tostring(string.format("%08x", block_type)) .. ", len: " .. tostring(block_len) .. " at offset " .. tostring(offset))
        offset = offset + block_len
      else
        break
      end
    end
  end
  print("Parsed " .. tostring(#packets) .. " packets from " .. tostring(filename))
  return packets, all_blocks
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
local pack_shb
pack_shb = function(shb)
  local endian = shb.endian or "<"
  local block_len = 28
  local header = sp(tostring(endian) .. "I4I4I4I2I2I8", shb.block_type, block_len, shb.byte_order_magic, shb.major_version, shb.minor_version, shb.section_length)
  return header .. sp(tostring(endian) .. "I4", block_len)
end
local pack_idb
pack_idb = function(idb)
  local endian = idb.endian or "<"
  local block_len = 20
  local header = sp(tostring(endian) .. "I4I4I2I2I4", idb.block_type, block_len, idb.linktype, idb.reserved, idb.snaplen)
  return header .. sp(tostring(endian) .. "I4", block_len)
end
local pack_epb
pack_epb = function(epb)
  local endian = epb.endian or "<"
  local packet_data = epb.packet_data
  local packet_len = #packet_data
  local padding_len = (4 - (packet_len % 4)) % 4
  local padding = string.rep("\0", padding_len)
  local block_len = 12 + packet_len + padding_len + 4
  local header = sp(tostring(endian) .. "I4I4I4I8I4", epb.block_type, block_len, epb.interface_id, epb.timestamp_hi, epb.timestamp_lo, epb.captured_len)
  return header .. packet_data .. padding .. sp(tostring(endian) .. "I4", block_len)
end
local write_pcapng
write_pcapng = function(filename, all_blocks)
  local parts = { }
  for _index_0 = 1, #all_blocks do
    local block = all_blocks[_index_0]
    local _exp_0 = block.type
    if "SHB" == _exp_0 then
      parts[#parts + 1] = pack_shb(block.data)
    elseif "IDB" == _exp_0 then
      parts[#parts + 1] = pack_idb(block.data)
    elseif "EPB" == _exp_0 then
      parts[#parts + 1] = pack_epb(block.data)
    else
      parts[#parts + 1] = block.raw_data
    end
  end
  local data = table.concat(parts)
  local f = io.open(filename, "wb")
  if not (f) then
    return nil, "Cannot open file for writing: " .. tostring(filename)
  end
  f:write(data)
  f:close()
  return true
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
  link_types = link_types,
  pack_shb = pack_shb,
  pack_idb = pack_idb,
  pack_epb = pack_epb,
  write_pcapng = write_pcapng
}
