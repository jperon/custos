local ethernet = require("ipparse.l2.ethernet")
local ip = require("ipparse.l3.ip")
local udp = require("ipparse.l4.udp")
local quic = require("ipparse.l4.quic.init")
local quic_v1 = require("ipparse.l4.quic.v1")
local quic_frames = require("ipparse.l4.quic.frames")
local ok, quic_crypto = pcall(require, "ipparse.l4.quic.crypto")
local reassembler = require("ipparse.lib.reassembler")
local tls = require("ipparse.l7.tls.init")
local handshake = require("ipparse.l7.tls.handshake.init")
local hello = require("ipparse.l7.tls.handshake.client_hello")
local sni = require("ipparse.l7.tls.handshake.extension.server_name")
local ipp = require("ipparse")
if not (ok) then
  print("Error: Failed to load 'ipparse.l4.quic.crypto'. Ensure it's available and Lunatik crypto is working.")
  print("Details: " .. tostring(quic_crypto))
  return 
end
local arg = arg
assert(arg[1], "Usage: quic_sni_parse.moon <frames_file>")
local file_content = nil
local file_handle = io.open(arg[1], "r")
if file_handle then
  file_content = file_handle:read("*a")
  file_handle:close()
else
  print("Error: Could not open file " .. tostring(arg[1]))
  return 
end
assert(file_content, "Failed to read file content from " .. tostring(arg[1]))
local frames_hex_strings
do
  local _accum_0 = { }
  local _len_0 = 1
  for frame in file_content:gmatch("[^,]+") do
    _accum_0[_len_0] = frame
    _len_0 = _len_0 + 1
  end
  frames_hex_strings = _accum_0
end
local frames
do
  local _accum_0 = { }
  local _len_0 = 1
  for _index_0 = 1, #frames_hex_strings do
    local s = frames_hex_strings[_index_0]
    _accum_0[_len_0] = ipp.hex2bin(s:gsub("%s", ""))
    _len_0 = _len_0 + 1
  end
  frames = _accum_0
end
print("--- Parsing QUIC SNI from Raw Packet ---")
local udp_dgrams = { }
for i, frame in ipairs(frames) do
  print("\n--- Parsing Frame " .. tostring(i) .. " ---")
  local eth_frame, l3_offset = ethernet.parse(frame)
  if not (eth_frame) then
    print("Error: Failed to parse Ethernet frame " .. tostring(i) .. ".")
    return 
  end
  print("\n-- Layer 2: Ethernet (Frame " .. tostring(i) .. ") --")
  print("Destination MAC: " .. tostring(ethernet.mac2s(eth_frame.dst)))
  print("Source MAC: " .. tostring(ethernet.mac2s(eth_frame.src)))
  print("EtherType: 0x" .. tostring(string.format("%04x", eth_frame.protocol)) .. " (" .. tostring(ethernet.proto[eth_frame.protocol] or "Unknown") .. ")")
  assert(eth_frame.protocol == ethernet.proto.IP4 or eth_frame.protocol == ethernet.proto.IP6, "Expected IPv4 or IPv6 packet for Frame " .. tostring(i))
  local ip_packet, l4_offset = ip.parse(frame, l3_offset, eth_frame.protocol)
  if not (ip_packet) then
    print("Error: Failed to parse IP packet " .. tostring(i) .. ".")
    return 
  end
  print("\n-- Layer 3: IP (Frame " .. tostring(i) .. ") --")
  print("Version: " .. tostring(ip_packet.version))
  print("Source IP: " .. tostring(ip.ip2s(ip_packet.src)))
  print("Destination IP: " .. tostring(ip.ip2s(ip_packet.dst)))
  print("Protocol: 0x" .. tostring(string.format("%02x", ip_packet.protocol)) .. " (" .. tostring(ip.proto[ip_packet.protocol] or "Unknown") .. ")")
  assert(ip_packet.protocol == ip.proto.UDP, "Expected UDP packet for QUIC in Frame " .. tostring(i))
  local udp_dgram, l7_offset = udp.parse(frame, l4_offset)
  if not (udp_dgram) then
    print("Error: Failed to parse UDP datagram " .. tostring(i) .. ".")
    return 
  end
  print("\n-- Layer 4: UDP (Frame " .. tostring(i) .. ") --")
  print("Source Port: " .. tostring(udp_dgram.spt))
  print("Destination Port: " .. tostring(udp_dgram.dpt))
  print("Length: " .. tostring(udp_dgram.len))
  assert(udp_dgram.dpt == 443 or udp_dgram.spt == 443, "Expected UDP port 443 for QUIC in Frame " .. tostring(i))
  table.insert(udp_dgrams, {
    frame,
    l7_offset
  })
end
local crypto_frames_data = { }
local quic_pkts = { }
for i, udp_dgram in ipairs(udp_dgrams) do
  print("\n--- Processing QUIC Packet in UDP Datagram " .. tostring(i) .. " ---")
  local quic_pkt, _ = quic.parse(udp_dgram[1], udp_dgram[2])
  if not (quic_pkt) then
    print("Error: Failed to parse QUIC packet from UDP datagram " .. tostring(i) .. ".")
    return 
  end
  print("QUIC Packet Type: " .. tostring(quic_pkt.type))
  print("QUIC Version: 0x" .. tostring(string.format("%x", quic_pkt.version)))
  print("Destination Connection ID: " .. tostring(ipp.bin2hex(quic_pkt.dst_connection_id)))
  print("Source Connection ID: " .. tostring(ipp.bin2hex(quic_pkt.src_connection_id)))
  assert(quic_pkt.type == quic.packet_type.INITIAL, "Expected Initial packet for SNI extraction")
  local client_secret, server_secret = quic_crypto.derive_initial_secrets(quic_pkt.dst_connection_id)
  local client_key, client_iv, client_hp = quic_crypto.derive_keys(client_secret)
  local unprotected_packet, packet_number = quic_crypto.remove_header_protection(udp_dgram[1], quic_pkt.pn_offset, quic_pkt.pn_length, client_hp)
  if not (unprotected_packet) then
    print("Error: Failed to remove header protection for packet " .. tostring(i) .. ".")
    return 
  end
  print("Packet Number: " .. tostring(packet_number))
  local decrypted_payload = quic_crypto.decrypt_payload(unprotected_packet, quic_pkt.payload_offset, packet_number, client_key, client_iv)
  if not (decrypted_payload) then
    print("Error: Failed to decrypt payload for packet " .. tostring(i) .. ".")
    return 
  end
  print("Decrypted Payload Length: " .. tostring(#decrypted_payload))
  for frame in quic_frames.iter_frames(decrypted_payload) do
    if frame.type == "CRYPTO" then
      print("Found CRYPTO frame in packet " .. tostring(i) .. ": Offset " .. tostring(frame.offset) .. ", Length " .. tostring(frame.len))
      table.insert(crypto_frames_data, {
        offset = frame.offset,
        data = frame.data
      })
    else
      print("Skipping non-CRYPTO frame type: " .. tostring(frame.type) .. " in packet " .. tostring(i))
    end
  end
  table.insert(quic_pkts, quic_pkt)
end
print("\n-- Reassembling CRYPTO Frames --")
local crypto_reassembler = reassembler()
local reassembled_crypto_data = nil
for i, cf in ipairs(crypto_frames_data) do
  reassembled_crypto_data = crypto_reassembler(cf.data, cf.offset, i == #crypto_frames_data)
end
if not (reassembled_crypto_data) then
  print("Error: Failed to reassemble CRYPTO data.")
  return 
end
print("Reassembled CRYPTO Data Length: " .. tostring(#reassembled_crypto_data))
print("\n-- Parsing TLS ClientHello and Extracting SNI --")
local hs_header, ch_offset = handshake.parse(reassembled_crypto_data, 1)
if not (hs_header) then
  print("Error: Failed to parse TLS Handshake message header.")
  return 
end
print("Handshake Message Type: " .. tostring(handshake.message_types[hs_header.type] or "Unknown") .. " (0x" .. tostring(string.format("%02x", hs_header.type)) .. ")")
print("Handshake Message Length: " .. tostring(hs_header.len))
assert(hs_header.type == handshake.message_types.client_hello, "Expected ClientHello message")
local ch_obj, _ = hello.parse(reassembled_crypto_data, ch_offset)
if not (ch_obj) then
  print("Error: Failed to parse ClientHello message structure.")
  return 
end
print("ClientHello Protocol Version: 0x" .. tostring(string.format("%04x", ch_obj.version)))
print("ClientHello Extensions Block Length (raw): " .. tostring(#ch_obj.extensions))
local sni_host = nil
for extension in handshake.iter_extensions(ch_obj.extensions) do
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
    else
      print("    Error: Failed to parse SNI data or no names found.")
    end
    break
  end
end
print("\n--- End of QUIC SNI Parsing Tutorial ---")
print("\n--- Running Assertions ---")
for i, frame in ipairs(frames) do
  local eth_frame, l3_offset = ethernet.parse(frame)
  local ip_packet, l4_offset = ip.parse(frame, l3_offset, eth_frame.protocol)
  local udp_dgram, l7_offset = udp.parse(frame, l4_offset)
  assert(eth_frame, "L2: Ethernet frame " .. tostring(i) .. " should be parsed")
  assert(eth_frame.protocol == ethernet.proto.IP4 or eth_frame.protocol == ethernet.proto.IP6, "L2: EtherType should be IP4 or IP6 for Frame " .. tostring(i))
  assert(ip_packet, "L3: IP packet " .. tostring(i) .. " should be parsed")
  assert(ip_packet.protocol == ip.proto.UDP, "L3: Protocol should be UDP for Frame " .. tostring(i))
  assert(udp_dgram, "L4: UDP datagram " .. tostring(i) .. " should be parsed")
  assert(udp_dgram.dpt == 443 or udp_dgram.spt == 443, "L4: UDP port should be 443 for Frame " .. tostring(i))
end
assert(#quic_pkts == #frames, "Expected a QUIC packet for each frame")
for i, quic_pkt in ipairs(quic_pkts) do
  assert(quic_pkt, "L4: QUIC packet " .. tostring(i) .. " should be parsed")
  assert(quic_pkt.type == quic.packet_type.INITIAL, "L4: QUIC Packet Type should be INITIAL for packet " .. tostring(i))
end
assert(reassembled_crypto_data, "Reassembled CRYPTO data should not be nil")
assert(hs_header, "TLS Handshake header should be parsed")
assert(hs_header.type == handshake.message_types.client_hello, "Handshake Type should be client_hello")
assert(ch_obj, "ClientHello object should be parsed")
assert(ch_obj.version == 0x0303, "ClientHello Protocol Version mismatch (expected TLS 1.2)")
assert(sni_host, "SNI: SNI host should be extracted")
assert(sni_host == "example.com", "SNI: Extracted SNI host mismatch")
return print("All assertions passed successfully!")
