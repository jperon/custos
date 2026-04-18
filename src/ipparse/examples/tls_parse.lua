local ethernet = require("ipparse.l2.ethernet")
local ip = require("ipparse.l3.ip")
local tcp = require("ipparse.l4.tcp")
local tls = require("ipparse.l7.tls.init")
local handshake = require("ipparse.l7.tls.handshake.init")
local hello = require("ipparse.l7.tls.handshake.client_hello")
local sni = require("ipparse.l7.tls.handshake.extension.server_name")
local ip_utils = require("ipparse.init")
local pkt_hex
if arg[1] then
  do
    local _with_0 = io.open(arg[1])
    pkt_hex = _with_0:read("*a")
    _with_0:close()
  end
  pkt_hex = table.concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    for line in pkt_hex:gmatch("[^\n]+") do
      _accum_0[_len_0] = line
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)())
  print(pkt_hex)
end
pkt_hex = pkt_hex or ("000102030405060708090a0b0800" .. "4500006F1234000040060000c0a80002c0a80001" .. "c00101bb00000001000000005018200000000000" .. "1603030042" .. "0100003E" .. "0303" .. "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" .. "00" .. "0002c02b" .. "0100" .. "0014" .. "0000" .. "0010" .. "000e" .. "00" .. "000b" .. "6578616d706c652e636f6d")
local raw_data = ip_utils.hex2bin(pkt_hex)
print("--- Parsing TLS SNI from Raw Packet ---")
local eth_frame, l3_offset = ethernet.parse(raw_data)
if not eth_frame then
  print("Error: Failed to parse Ethernet frame.")
  return 
end
print("\n-- Layer 2: Ethernet --")
print("Destination MAC: " .. tostring(ethernet.mac2s(eth_frame.dst)))
print("Source MAC: " .. tostring(ethernet.mac2s(eth_frame.src)))
print("EtherType: 0x" .. tostring(string.format("%04x", eth_frame.protocol)) .. " (" .. tostring(ethernet.proto[eth_frame.protocol] or "Unknown") .. ")")
if eth_frame.protocol ~= ethernet.proto.IP4 and eth_frame.protocol ~= ethernet.proto.IP6 then
  print("Error: Not an IP packet. EtherType: 0x" .. tostring(string.format("%04x", eth_frame.protocol)))
  return 
end
local ip_packet, l4_offset = ip.parse(raw_data, l3_offset, eth_frame.protocol)
if not ip_packet then
  print("Error: Failed to parse IP packet.")
  return 
end
print("\n-- Layer 3: IP --")
print("Version: " .. tostring(ip_packet.version))
print("Source IP: " .. tostring(ip.ip2s(ip_packet.src)))
print("Destination IP: " .. tostring(ip.ip2s(ip_packet.dst)))
print("Protocol: 0x" .. tostring(string.format("%02x", ip_packet.protocol)) .. " (" .. tostring(ip.proto[ip_packet.protocol] or "Unknown") .. ")")
if ip_packet.protocol ~= ip.proto.TCP then
  print("Error: Not a TCP packet. IP Protocol: 0x" .. tostring(string.format("%02x", ip_packet.protocol)))
  return 
end
local tcp_seg, l7_offset = tcp.parse(raw_data, l4_offset)
if not tcp_seg then
  print("Error: Failed to parse TCP segment.")
  return 
end
print("\n-- Layer 4: TCP --")
print("Source Port: " .. tostring(tcp_seg.spt))
print("Destination Port: " .. tostring(tcp_seg.dpt))
print("Sequence Number: " .. tostring(tcp_seg.seq_n))
local flags_list = { }
if tcp_seg.SYN then
  flags_list[#flags_list + 1] = "SYN"
end
if tcp_seg.ACK then
  flags_list[#flags_list + 1] = "ACK"
end
if tcp_seg.FIN then
  flags_list[#flags_list + 1] = "FIN"
end
if tcp_seg.RST then
  flags_list[#flags_list + 1] = "RST"
end
if tcp_seg.PSH then
  flags_list[#flags_list + 1] = "PSH"
end
if tcp_seg.URG then
  flags_list[#flags_list + 1] = "URG"
end
print("Flags: " .. tostring(table.concat(flags_list, " ")) .. " (0x" .. tostring(string.format("%02x", tcp_seg.flags)) .. ")")
print("\n-- Layer 7: TLS --")
local tls_record, tls_offset = tls.parse(raw_data, l7_offset)
if not tls_record then
  print("Error: Failed to parse TLS Record.")
  return 
end
print("TLS Record Type: 0x" .. tostring(string.format("%02x", tls_record.type)) .. " (" .. tostring(tls.record_types[tls_record.type] or "Unknown") .. ")")
print("TLS Version in Record: 0x" .. tostring(string.format("%02x%02x", tls_record.ver, tls_record.subver)))
print("TLS Record Payload Length: " .. tostring(tls_record.len))
if tls_record.type ~= tls.record_types.handshake then
  print("Error: Not a TLS Handshake record. Record Type: 0x" .. tostring(string.format("%02x", tls_record.type)))
  return 
end
local hs_header, ch_offset = handshake.parse(raw_data, tls_offset)
if not hs_header then
  print("Error: Failed to parse TLS Handshake message header.")
  return 
end
print("Handshake Message Type: 0x" .. tostring(string.format("%02x", hs_header.type)) .. " (" .. tostring(handshake.message_types[hs_header.type] or "Unknown") .. ")")
print("Handshake Message Length: " .. tostring(hs_header.len))
if hs_header.type ~= handshake.message_types.client_hello then
  print("Error: Not a ClientHello message. Handshake Type: 0x" .. tostring(string.format("%02x", hs_header.type)))
  return 
end
local ch_obj, _ = hello.parse(raw_data, ch_offset)
if not ch_obj then
  print("Error: Failed to parse ClientHello message structure.")
  return 
end
print("ClientHello Protocol Version: 0x" .. tostring(string.format("%04x", ch_obj.version)))
print("ClientHello Extensions Block Length (raw): " .. tostring(#ch_obj.extensions))
local sni_host = nil
for extension in handshake.iter_extensions(ch_obj.extensions) do
  local ext_name = handshake.extensions[extension.type] or "Unknown"
  print("  Found Extension: Type 0x" .. tostring(string.format("%04x", extension.type)) .. " (" .. tostring(ext_name) .. "), Data Length " .. tostring(#extension.data))
  if extension.type == handshake.extensions.server_name then
    print("  > Found Server Name Indication (SNI) Extension")
    local sni_list = sni.parse(extension.data)
    if sni_list and sni_list.names and #sni_list.names > 0 then
      local name_entry = sni_list.names[1]
      if name_entry and name_entry.type == sni.name_types.HOST_NAME then
        sni_host = name_entry.name
        print("    SNI Host Name: " .. tostring(sni_host))
      else
        print("    Warning: First SNI entry not of type host_name or not found.")
      end
      if sni_list.incomplete then
        print("    Warning: SNI ServerNameList parsing was incomplete. " .. tostring(err_msg or ''))
      end
    else
      print("    Error: Failed to parse SNI data using server_name_parser or no names found. " .. tostring(err_msg or ''))
    end
    break
  end
end
if arg[1] then
  os.exit()
end
print("\n--- End of SNI Parsing Tutorial ---")
print("\n--- Running Assertions ---")
assert(eth_frame, "Ethernet frame should be parsed")
assert(ethernet.mac2s(eth_frame.dst) == "00:01:02:03:04:05", "L2 Dst MAC mismatch")
assert(ethernet.mac2s(eth_frame.src) == "06:07:08:09:0a:0b", "L2 Src MAC mismatch")
assert(eth_frame.protocol == ethernet.proto.IP4, "L2 EtherType should be IP4")
assert(string.format("%04x", eth_frame.protocol) == "0800", "L2 EtherType hex mismatch")
assert(ethernet.proto[eth_frame.protocol] == "IP4", "L2 EtherType name mismatch")
assert(ip_packet, "IP packet should be parsed")
assert(ip_packet.version == 4, "L3 IP Version mismatch")
assert(ip.ip2s(ip_packet.src) == "192.168.0.2", "L3 Source IP mismatch")
assert(ip.ip2s(ip_packet.dst) == "192.168.0.1", "L3 Destination IP mismatch")
assert(ip_packet.protocol == ip.proto.TCP, "L3 Protocol should be TCP")
assert(string.format("%02x", ip_packet.protocol) == "06", "L3 Protocol hex mismatch")
assert(ip.proto[ip_packet.protocol] == "TCP", "L3 Protocol name mismatch")
assert(tcp_seg, "TCP segment should be parsed")
assert(tcp_seg.spt == 49153, "L4 TCP Source Port mismatch")
assert(tcp_seg.dpt == 443, "L4 TCP Destination Port mismatch")
assert(tcp_seg.seq_n == 1, "L4 TCP Sequence Number mismatch")
assert(tcp_seg.ACK == true, "L4 TCP ACK flag should be true")
assert(tcp_seg.PSH == true, "L4 TCP PSH flag should be true")
assert(not tcp_seg.SYN, "L4 TCP SYN flag should be false")
assert(not tcp_seg.FIN, "L4 TCP FIN flag should be false")
assert(not tcp_seg.RST, "L4 TCP RST flag should be false")
assert(not tcp_seg.URG, "L4 TCP URG flag should be false")
local flags_list_assert = { }
if tcp_seg.SYN then
  flags_list_assert[#flags_list_assert + 1] = "SYN"
end
if tcp_seg.ACK then
  flags_list_assert[#flags_list_assert + 1] = "ACK"
end
if tcp_seg.FIN then
  flags_list_assert[#flags_list_assert + 1] = "FIN"
end
if tcp_seg.RST then
  flags_list_assert[#flags_list_assert + 1] = "RST"
end
if tcp_seg.PSH then
  flags_list_assert[#flags_list_assert + 1] = "PSH"
end
if tcp_seg.URG then
  flags_list_assert[#flags_list_assert + 1] = "URG"
end
assert(table.concat(flags_list_assert, " ") == "ACK PSH", "L4 TCP Flags string mismatch")
assert(tcp_seg.flags == 0x18, "L4 TCP Flags raw value mismatch")
assert(string.format("%02x", tcp_seg.flags) == "18", "L4 TCP Flags hex string mismatch")
assert(tls_record, "TLS Record should be parsed")
assert(tls_record.type == tls.record_types.handshake, "L7 TLS Record Type should be handshake")
assert(string.format("%02x", tls_record.type) == "16", "L7 TLS Record Type hex mismatch")
assert(tls.record_types[tls_record.type] == "handshake", "L7 TLS Record Type name mismatch")
assert(tls_record.ver == 0x03 and tls_record.subver == 0x03, "L7 TLS Version mismatch (expected 0x0303)")
assert(string.format("%02x%02x", tls_record.ver, tls_record.subver) == "0303", "L7 TLS Version string mismatch")
assert(tls_record.len == 66, "L7 TLS Record Payload Length mismatch")
assert(hs_header, "TLS Handshake message header should be parsed")
assert(hs_header.type == handshake.message_types.client_hello, "L7 Handshake Type should be client_hello")
assert(string.format("%02x", hs_header.type) == "01", "L7 Handshake Type hex mismatch")
assert(handshake.message_types[hs_header.type] == "client_hello", "L7 Handshake Type name mismatch")
assert(hs_header.len == 62, "L7 Handshake Message Length mismatch")
assert(ch_obj, "ClientHello object should be parsed")
assert(ch_obj.version == 0x0303, "L7 ClientHello Protocol Version mismatch")
assert(string.format("%04x", ch_obj.version) == "0303", "L7 ClientHello Protocol Version string mismatch")
assert(#ch_obj.extensions == 20, "L7 ClientHello Extensions Block Length mismatch")
assert(sni_host == "example.com", "L7 SNI Host Name mismatch")
return print("All assertions passed successfully!")
