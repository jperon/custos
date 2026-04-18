local su
su = string.unpack
print("=== Simple PCAPNG Debug ===")
local file = io.open("quic.pcapng", "rb")
local data = file:read("*all")
file:close()
print("File size: " .. tostring(#data) .. " bytes")
local offset = 1
local block_count = 0
while offset <= #data and block_count < 20 do
  if offset + 8 > #data then
    break
  end
  local block_type = su("<I4", data, offset)
  local block_len = su("<I4", data, offset + 4)
  print("Block " .. tostring(block_count + 1) .. " at offset " .. tostring(offset) .. ":")
  print("  Type: 0x" .. tostring(string.format("%08x", block_type)))
  print("  Length: " .. tostring(block_len))
  local _exp_0 = block_type
  if 0x0A0D0D0A == _exp_0 then
    print("  -> Section Header Block (SHB)")
  elseif 0x00000001 == _exp_0 then
    print("  -> Interface Description Block (IDB)")
  elseif 0x00000006 == _exp_0 then
    print("  -> Enhanced Packet Block (EPB)")
    if offset + 28 + 20 <= #data then
      local packet_start = offset + 28
      local packet_preview = ""
      for i = 0, 19 do
        local byte_val = su("B", data, packet_start + i)
        packet_preview = packet_preview .. string.format("%02x ", byte_val)
      end
      print("  -> Packet preview: " .. tostring(packet_preview))
    end
  else
    print("  -> Unknown block type")
  end
  if block_len <= 0 or block_len > #data - offset + 1 then
    break
  end
  offset = offset + block_len
  block_count = block_count + 1
  print("")
end
print("Processed " .. tostring(block_count) .. " blocks")
print("\n=== Manual EPB Analysis ===")
local epb_offset = nil
offset = 1
while offset <= #data do
  if offset + 8 > #data then
    break
  end
  local block_type = su("<I4", data, offset)
  local block_len = su("<I4", data, offset + 4)
  if block_type == 0x00000006 then
    epb_offset = offset
    print("Found EPB at offset " .. tostring(offset))
    break
  end
  offset = offset + block_len
end
if epb_offset then
  local block_type, block_len, interface_id, ts_high, ts_low, captured_len, original_len = su("<I4I4I4I4I4I4I4", data, epb_offset)
  print("EPB Details:")
  print("  Block type: 0x" .. tostring(string.format("%08x", block_type)))
  print("  Block length: " .. tostring(block_len))
  print("  Interface ID: " .. tostring(interface_id))
  print("  Timestamp high: " .. tostring(ts_high))
  print("  Timestamp low: " .. tostring(ts_low))
  print("  Captured length: " .. tostring(captured_len))
  print("  Original length: " .. tostring(original_len))
  local packet_start = epb_offset + 28
  print("  Packet data starts at offset " .. tostring(packet_start))
  if packet_start + captured_len <= #data then
    print("  Packet data is within file bounds")
    local packet_hex = ""
    for i = 0, math.min(31, captured_len - 1) do
      local byte_val = su("B", data, packet_start + i)
      packet_hex = packet_hex .. string.format("%02x", byte_val)
      if (i + 1) % 8 == 0 then
        packet_hex = packet_hex .. " "
      end
    end
    return print("  First 32 bytes: " .. tostring(packet_hex))
  else
    return print("  ERROR: Packet data extends beyond file!")
  end
else
  return print("No EPB blocks found")
end
