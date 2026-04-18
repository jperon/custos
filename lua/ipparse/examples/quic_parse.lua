local eth = require("ipparse.l2.ethernet")
local ip = require("ipparse.l3.ip")
local udp = require("ipparse.l4.udp")
local quic = require("ipparse.l7.quic")
local hs = require("ipparse.l7.tls.handshake.init")
local ch_hello = require("ipparse.l7.tls.handshake.client_hello")
local sni = require("ipparse.l7.tls.handshake.extension.server_name")
local ipu = require("ipparse.init")
local tls_ch_hex = "0100003E" .. "0303" .. "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" .. "00" .. "0002c02b" .. "0100" .. "0014" .. "0000" .. "0010" .. "000e" .. "00" .. "000b" .. "6578616d706c652e636f6d"
local crypto_frame_data_len = #tls_ch_hex / 2
local crypto_frame_len_hex = string.format("%04x", (0x4000 | crypto_frame_data_len))
local quic_crypto_frame_hex = "060000" .. crypto_frame_len_hex .. tls_ch_hex
local packet_number_hex = "00"
local quic_frames_hex = quic_crypto_frame_hex
local initial_salt_v1_hex = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
local dcid_hex = "aaaaaaaaaaaaaaaa"
local simulated_hp_keystream_hex = string.sub(dcid_hex, 1, 10)
local simulated_pp_keystream_hex = dcid_hex .. dcid_hex
local xor_hex_strings
xor_hex_strings = function(hex_a, hex_b)
  local bin_a = ipu.hex2bin(hex_a)
  local bin_b = ipu.hex2bin(hex_b)
  local result_bin = ""
  local min_len = math.min(#bin_a, #bin_b)
  for i = 1, min_len do
    result_bin = result_bin .. string.char(string.byte(bin_a, i)(~string.byte(bin_b, i)))
  end
  if #bin_a > min_len then
    result_bin = result_bin .. string.sub(bin_a, min_len + 1)
  elseif #bin_b > min_len then
    result_bin = result_bin .. string.sub(bin_b, min_len + 1)
  end
  return ipu.bin2hex(result_bin)
end
local first_byte_unprotected_hex = "c0"
local header_to_protect_hex = first_byte_unprotected_hex .. packet_number_hex
local hp_keystream_segment_hex = string.sub(simulated_hp_keystream_hex, 1, #header_to_protect_hex)
local protected_header_segment_hex = xor_hex_strings(header_to_protect_hex, hp_keystream_segment_hex)
local first_byte_protected_hex = string.sub(protected_header_segment_hex, 1, 2)
local protected_packet_number_hex = string.sub(protected_header_segment_hex, 3)
local quic_len_val = (#protected_packet_number_hex / 2) + (#quic_frames_hex / 2) + 16
local quic_len_hex_varint = ""
if quic_len_val < 64 then
  quic_len_hex_varint = string.format("%02x", quic_len_val)
elseif quic_len_val < 16384 then
  quic_len_hex_varint = string.format("%04x", (0x4000 | quic_len_val))
else
  quic_len_hex_varint = string.format("%08x", (0x80000000 | quic_len_val))
end
local quic_header_prefix_hex = first_byte_protected_hex .. "00000001" .. "08" .. dcid_hex .. "08bbbbbbbbbbbbbbbb" .. "00" .. quic_len_hex_varint
local pp_keystream_segment_hex = string.sub(simulated_pp_keystream_hex, 1, #quic_frames_hex)
local protected_frames_hex = xor_hex_strings(quic_frames_hex, pp_keystream_segment_hex)
local auth_tag_hex = "00000000000000000000000000000000"
local quic_packet_hex = quic_header_prefix_hex .. protected_packet_number_hex .. protected_frames_hex .. auth_tag_hex
local udp_len_hex = string.format("%04x", 8 + (#quic_packet_hex / 2))
local udp_header_hex = "c00201bb" .. udp_len_hex .. "0000"
local ip_total_len = 20 + (#udp_header_hex / 2) + (#quic_packet_hex / 2)
local ip_total_len_hex = string.format("%04x", ip_total_len)
local ip_header_hex = "4500" .. ip_total_len_hex .. "1234000040110000c0a80002c0a80001"
local eth_header_hex = "000102030405060708090a0b0800"
local pkt_hex_quic = eth_header_hex .. ip_header_hex .. udp_header_hex .. quic_packet_hex
local raw_data = ipu.hex2bin(pkt_hex_quic)
print("--- Parsing QUIC SNI from Raw Packet ---")
local eth_frame, l3_offset = eth.parse(raw_data)
if not (eth_frame) then
  print("Error: Failed to parse Ethernet frame.")
  return 
end
print("\n-- Layer 2: Ethernet --")
print("Destination MAC: " .. tostring(eth.mac2s(eth_frame.dst)))
print("Source MAC: " .. tostring(eth.mac2s(eth_frame.src)))
print("EtherType: 0x" .. tostring(string.format("%04x", eth_frame.protocol)) .. " (" .. tostring(eth.proto[eth_frame.protocol] or "Unknown") .. ")")
assert(eth_frame.protocol == eth.proto.IP4, "Expected IPv4 packet")
local ip_pkt, l4_offset = ip.parse(raw_data, l3_offset, eth_frame.protocol)
if not (ip_pkt) then
  print("Error: Failed to parse IP packet.")
  return 
end
print("\n-- Layer 3: IP --")
print("Version: " .. tostring(ip_pkt.version))
print("Source IP: " .. tostring(ip.ip2s(ip_pkt.src)))
print("Destination IP: " .. tostring(ip.ip2s(ip_pkt.dst)))
print("Protocol: 0x" .. tostring(string.format("%02x", ip_pkt.protocol)) .. " (" .. tostring(ip.proto[ip_pkt.protocol] or "Unknown") .. ")")
assert(ip_pkt.protocol == ip.proto.UDP, "Expected UDP packet")
local udp_dgram, l7_offset = udp.parse(raw_data, l4_offset)
if not (udp_dgram) then
  print("Error: Failed to parse UDP datagram.")
  return 
end
print("\n-- Layer 4: UDP --")
print("Source Port: " .. tostring(udp_dgram.spt))
print("Destination Port: " .. tostring(udp_dgram.dpt))
print("Length: " .. tostring(udp_dgram.len))
print("\n-- Layer 7: QUIC --")
local quic_pkt, _ = quic.parse(raw_data, l7_offset, {
  is_client = true
})
if not (quic_pkt) then
  print("Error: Failed to parse QUIC packet.")
  return 
end
print("QUIC Header Form: " .. tostring(quic_pkt.header_form))
if quic_pkt.header_form == quic.header_forms.LONG then
  print("QUIC Long Packet Type: " .. tostring(quic.long_packet_types[quic_pkt.type] or "Unknown") .. " (" .. tostring(string.format("%02x", quic_pkt.type)) .. ")")
  print("QUIC Version: 0x" .. tostring(string.format("%08x", quic_pkt.version)))
  print("QUIC DCID: " .. tostring(ipu.bin2hex(quic_pkt.dcid)))
  print("QUIC SCID: " .. tostring(ipu.bin2hex(quic_pkt.scid)))
end
local sni_host = nil
local ch_obj_quic = nil
local _list_0 = quic_pkt.frames
for _index_0 = 1, #_list_0 do
  local _continue_0 = false
  repeat
    local frame = _list_0[_index_0]
    if frame.type == quic.frame_types.CRYPTO then
      print("  Found QUIC CRYPTO Frame, Offset: " .. tostring(frame.offset) .. ", Length: " .. tostring(frame.len))
      local hs_header_quic, ch_data_offset = hs.parse(frame.data, 0)
      if not (hs_header_quic and hs_header_quic.type == hs.message_types.client_hello) then
        print("    Error: Not a ClientHello message in CRYPTO frame or failed to parse.")
        _continue_0 = true
        break
      end
      print("    TLS Handshake Message Type: client_hello")
      print("    TLS Handshake Message Length: " .. tostring(hs_header_quic.len))
      ch_obj_quic, _ = ch_hello.parse(frame.data, ch_data_offset)
      if not (ch_obj_quic) then
        print("    Error: Failed to parse ClientHello structure from CRYPTO frame.")
        _continue_0 = true
        break
      end
      print("    ClientHello Protocol Version: 0x" .. tostring(string.format("%04x", ch_obj_quic.version)))
      print("    ClientHello Extensions Block Length (raw): " .. tostring(#ch_obj_quic.extensions))
      for extension in hs.iter_extensions(ch_obj_quic.extensions) do
        local ext_name = hs.extensions[extension.type] or "Unknown"
        if extension.type == hs.extensions.server_name then
          print("      > Found Server Name Indication (SNI) Extension")
          local sni_list_obj = sni.parse(extension.data)
          if sni_list_obj and sni_list_obj.names and #sni_list_obj.names > 0 then
            local name_entry = sni_list_obj.names[1]
            if name_entry and name_entry.type == sni.name_types.HOST_NAME then
              sni_host = name_entry.name
              print("        SNI Host Name: " .. tostring(sni_host))
            else
              print("        Warning: First SNI entry not of type host_name or not found.")
            end
            if sni_list_obj and sni_list_obj.incomplete then
              print("        Warning: SNI ServerNameList parsing was incomplete.")
            end
          else
            print("        Error: Failed to parse SNI data or no names found.")
          end
          break
        end
      end
      if sni_host then
        break
      end
    end
    _continue_0 = true
  until true
  if not _continue_0 then
    break
  end
end
print("\n--- End of QUIC SNI Parsing Tutorial ---")
print("\n--- Running Assertions ---")
assert(eth_frame, "Ethernet frame should be parsed")
assert(eth.mac2s(eth_frame.dst) == "00:01:02:03:04:05", "L2 Dst MAC mismatch")
assert(eth_frame.protocol == eth.proto.IP4, "L2 EtherType should be IP4")
assert(ip_pkt, "IP packet should be parsed")
assert(ip_pkt.protocol == ip.proto.UDP, "L3 Protocol should be UDP")
assert(udp_dgram, "UDP datagram should be parsed")
assert(udp_dgram.dpt == 443, "L4 UDP Destination Port should be 443")
assert(quic_pkt, "QUIC packet should be parsed")
assert(quic_pkt.header_form == quic.header_forms.LONG, "QUIC Header Form mismatch")
assert(quic_pkt.type == quic.long_packet_types.INITIAL, "QUIC Packet Type mismatch")
assert(quic_pkt.version == 0x00000001, "QUIC Version mismatch")
assert(ch_obj_quic, "ClientHello object from QUIC should be parsed")
assert(ch_obj_quic.version == 0x0303, "L7 ClientHello Protocol Version mismatch")
assert(#ch_obj_quic.extensions == 20, "L7 ClientHello Extensions Block Length mismatch")
assert(sni_host == "example.com", "L7 SNI Host Name mismatch")
return print("All assertions passed successfully!")
