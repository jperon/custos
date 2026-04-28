local bin2hex
bin2hex = require("ipparse.init").bin2hex
local su
su = string.unpack
local lshift
lshift = require("ipparse.lib.bit_compat").lshift
print("=== Working PCAP Test ===")
local file = io.open("quic.pcapng", "rb")
local data = file:read("*all")
file:close()
print("File size: " .. tostring(#data) .. " bytes")
local packets = { }
local offset = 1
offset = 129
offset = 229
while offset <= #data do
  if offset + 8 > #data then
    break
  end
  local block_type = su("<I4", data, offset)
  local block_len = su("<I4", data, offset + 4)
  if block_type ~= 0x00000006 then
    print("Found non-EPB block at offset " .. tostring(offset) .. ", type: 0x" .. tostring(string.format("%08x", block_type)))
    break
  end
  local interface_id, ts_high, ts_low, captured_len, original_len
  block_type, block_len, interface_id, ts_high, ts_low, captured_len, original_len = su("<I4I4I4I4I4I4I4", data, offset)
  local packet_start = offset + 28
  local packet_data = data:sub(packet_start, packet_start + captured_len - 1)
  local packet = {
    packet_num = #packets + 1,
    interface_id = interface_id,
    ts_high = ts_high,
    ts_low = ts_low,
    captured_len = captured_len,
    original_len = original_len,
    packet_data = packet_data,
    timestamp = lshift(ts_high, 32) + ts_low
  }
  packets[#packets + 1] = packet
  print("Parsed packet " .. tostring(#packets) .. ", size " .. tostring(captured_len) .. " bytes")
  offset = offset + block_len
end
print("Total packets parsed: " .. tostring(#packets))
print("")
local eth = require("ipparse.l2.ethernet")
local ip = require("ipparse.l3.ip")
local udp = require("ipparse.l4.udp")
local quic = require("ipparse.l4.quic")
local quic_packets = { }
for i, packet in ipairs(packets) do
  local _continue_0 = false
  repeat
    print("=== Analyzing Packet " .. tostring(i) .. " ===")
    local hex_preview = bin2hex(packet.packet_data:sub(1, math.min(64, #packet.packet_data)))
    print("Raw data: " .. tostring(hex_preview))
    local eth_frame, l3_offset = eth.parse(packet.packet_data)
    if not (eth_frame) then
      print("Failed to parse Ethernet frame")
      _continue_0 = true
      break
    end
    print("Ethernet: " .. tostring(eth.proto[eth_frame.protocol] or string.format("0x%04x", eth_frame.protocol)))
    local ip_pkt, l4_offset = ip.parse(packet.packet_data, l3_offset, eth_frame.protocol)
    if not (ip_pkt) then
      print("Failed to parse IP packet")
      _continue_0 = true
      break
    end
    local src_ip = ip.ip2s(ip_pkt.src)
    local dst_ip = ip.ip2s(ip_pkt.dst)
    print("IP: " .. tostring(src_ip) .. " -> " .. tostring(dst_ip) .. ", protocol " .. tostring(ip_pkt.protocol))
    if not (ip_pkt.protocol == ip.proto.UDP) then
      print("Not UDP packet")
      _continue_0 = true
      break
    end
    local udp_dgram, l7_offset = udp.parse(packet.packet_data, l4_offset)
    if not (udp_dgram) then
      print("Failed to parse UDP datagram")
      _continue_0 = true
      break
    end
    print("UDP: " .. tostring(udp_dgram.spt) .. " -> " .. tostring(udp_dgram.dpt))
    if not (udp_dgram.dpt == 443 or udp_dgram.spt == 443) then
      print("Not on QUIC port 443")
      _continue_0 = true
      break
    end
    print("Attempting QUIC parsing at offset " .. tostring(l7_offset) .. "...")
    local quic_data = packet.packet_data:sub(l7_offset)
    print("QUIC data (first 32 bytes): " .. tostring(bin2hex(quic_data:sub(1, math.min(32, #quic_data)))))
    local quic_pkt, _ = quic.parse(packet.packet_data, l7_offset)
    if quic_pkt then
      print("✓ QUIC header parsed successfully!")
      if quic_pkt.long_header then
        local dcid = bin2hex(quic_pkt.dst_connection_id)
        local scid = bin2hex(quic_pkt.src_connection_id or "")
        print("  Long header - Version: 0x" .. tostring(string.format("%08x", quic_pkt.version)))
        print("  DCID: " .. tostring(dcid))
        print("  SCID: " .. tostring(scid))
        local quic_packet = {
          packet_num = i,
          eth_frame = eth_frame,
          ip_pkt = ip_pkt,
          udp_dgram = udp_dgram,
          quic_pkt = quic_pkt,
          raw_data = packet.packet_data,
          quic_offset = l7_offset
        }
        quic_packets[#quic_packets + 1] = quic_packet
      else
        local dcid = bin2hex(quic_pkt.dst_connection_id)
        print("  Short header - DCID: " .. tostring(dcid))
      end
    else
      print("✗ Failed to parse QUIC header")
    end
    print("")
    _continue_0 = true
  until true
  if not _continue_0 then
    break
  end
end
print("=== QUIC Summary ===")
print("Total QUIC packets found: " .. tostring(#quic_packets))
local expected_dcid = "133a971cdef32a97"
local expected_scid = "fb0a4d"
local matching_packets = 0
for _index_0 = 1, #quic_packets do
  local pkt = quic_packets[_index_0]
  local dcid = bin2hex(pkt.quic_pkt.dst_connection_id)
  local scid = bin2hex(pkt.quic_pkt.src_connection_id or "")
  if dcid == expected_dcid and scid == expected_scid then
    matching_packets = matching_packets + 1
  end
end
print("Packets matching expected connection IDs: " .. tostring(matching_packets))
print("Expected DCID: " .. tostring(expected_dcid))
print("Expected SCID: " .. tostring(expected_scid))
if matching_packets > 0 then
  return print("✓ SUCCESS: Found QUIC packets with expected connection IDs!")
else
  return print("⚠ No packets match expected connection IDs")
end
