local bin2hex, hexdump
do
  local _obj_0 = require("ipparse.init")
  bin2hex, hexdump = _obj_0.bin2hex, _obj_0.hexdump
end
local su
su = string.unpack
print("=== PCAPNG File Debug ===")
local file = io.open("quic.pcapng", "rb")
if not (file) then
  print("Could not open quic.pcapng")
  os.exit(1)
end
local data = file:read("*all")
file:close()
print("File size: " .. tostring(#data) .. " bytes")
print("")
print("=== First 256 bytes ===")
print(hexdump(data:sub(1, math.min(256, #data))))
print("")
local offset = 1
local block_count = 0
while offset <= #data and block_count < 10 do
  if offset + 8 > #data then
    print("Not enough data for block header at offset " .. tostring(offset))
    break
  end
  local block_type, block_len = su("<I4I4", data, offset)
  print("=== Block " .. tostring(block_count + 1) .. " at offset " .. tostring(offset) .. " ===")
  print("Block type: 0x" .. tostring(string.format("%08x", block_type)))
  print("Block length: " .. tostring(block_len))
  local block_names = {
    [0x0A0D0D0A] = "SHB (Section Header Block)",
    [0x00000001] = "IDB (Interface Description Block)",
    [0x00000006] = "EPB (Enhanced Packet Block)",
    [0x00000002] = "PB (Packet Block)",
    [0x00000003] = "SPB (Simple Packet Block)"
  }
  if block_names[block_type] then
    print("Recognized: " .. tostring(block_names[block_type]))
  else
    print("Unknown block type")
  end
  if offset + math.min(64, block_len) <= #data then
    local block_data = data:sub(offset, offset + math.min(64, block_len) - 1)
    print("Block data (first 64 bytes):")
    print(hexdump(block_data))
  end
  if block_len <= 0 or block_len > #data then
    print("Invalid block length: " .. tostring(block_len))
    break
  end
  if offset + block_len > #data then
    print("Block extends beyond file end")
    break
  end
  print("")
  offset = offset + block_len
  block_count = block_count + 1
end
print("Processed " .. tostring(block_count) .. " blocks")
return print("Final offset: " .. tostring(offset) .. ", file size: " .. tostring(#data))
