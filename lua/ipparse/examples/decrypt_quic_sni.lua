local pcap = require("ipparse.lib.pcap")
local bin2hex
bin2hex = require("ipparse.init").bin2hex
local quic_decrypt = require("ipparse.l4.quic.decrypt")
local quic_l7 = require("ipparse.l7.quic")
print("🔍 Decrypting SNI from QUIC packets in quic.pcapng")
print("")
local pcap_file = "quic.pcapng"
local connection_id = "133a971cdef32a97"
local file = io.open(pcap_file, "rb")
if file then
  local raw_data = file:read("*all")
  print("File size: " .. tostring(#raw_data) .. " bytes")
  print("File hex preview: " .. tostring(bin2hex(raw_data:sub(1, math.min(64, #raw_data)))))
  file:close()
end
if not file then
  error("❌ File not found: " .. tostring(pcap_file))
else
  print("✅ File found: " .. tostring(pcap_file))
  file:close()
end
local packets = pcap.parse_pcapng(pcap_file)
print("Parsed " .. tostring(#packets) .. " packets from " .. tostring(pcap_file))
print("Loaded " .. tostring(#packets) .. " packets from " .. tostring(pcap_file))
local filtered_packets = { }
for i, packet in ipairs(packets) do
  print("Packet " .. tostring(i) .. ": Timestamp=" .. tostring(packet.timestamp) .. ", Length=" .. tostring(#packet.packet_data))
  if packet.connection_id then
    print("  Connection ID: " .. tostring(packet.connection_id))
  else
    print("  ❌ No connection ID found in packet")
  end
  if packet.connection_id == connection_id then
    filtered_packets[#filtered_packets + 1] = packet
  end
end
print("Filtered " .. tostring(#filtered_packets) .. " packets for connection ID " .. tostring(connection_id))
local decryption_results = quic_decrypt.decrypt_quic_packets(connection_id, filtered_packets)
local all_frames = { }
for _index_0 = 1, #decryption_results do
  local result = decryption_results[_index_0]
  if result.success then
    local _list_0 = result.frames
    for _index_1 = 1, #_list_0 do
      local frame = _list_0[_index_1]
      all_frames[#all_frames + 1] = frame
    end
  end
end
print("Collected " .. tostring(#all_frames) .. " frames from decrypted packets")
local l7_parser = quic_l7.QuicL7Parser()
local sni = l7_parser:process_frames(all_frames)
if sni then
  return print("🎉 SUCCESS: Extracted SNI '" .. tostring(sni) .. "'")
else
  return print("❌ FAILED: No SNI found in the packets")
end
