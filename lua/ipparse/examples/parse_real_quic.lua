do
  local script_path = (arg and arg[0]) or ""
  if script_path == "" and debug and debug.getinfo then
    local src = debug.getinfo(1, "S").source or ""
    if src:sub(1, 1) == "@" then
      script_path = src:sub(2)
    end
  end
  local script_dir = script_path:match("^(.*)/[^/]+$") or "."
  local project_root = tostring(script_dir) .. "/.."
  local module_root = tostring(project_root) .. "/.."
  package.path = table.concat({
    package.path,
    tostring(module_root) .. "/?.lua",
    tostring(module_root) .. "/?/init.lua"
  }, ";")
  local ok_ffi = pcall(require, "ffi")
  if not (ok_ffi) then
    package.preload.ffi = function()
      return require("ipparse.lib.ffi_stub")
    end
  end
end
local pack_compat = require("ipparse.lib.pack_compat")
pack_compat.inject()
local util = require("ipparse.lib.util")
local eth = require("ipparse.l2.ethernet")
local ip = require("ipparse.l3.ip")
local udp = require("ipparse.l4.udp")
local quic_mod = require("ipparse.l4.quic")
local quic_session = require("ipparse.l7.quic.session")
local su
su = pack_compat.unpack
local bin2hex = util.bin2hex
local parse_pcap
parse_pcap = function(filename)
  local file = io.open(filename, "rb")
  if not (file) then
    error("Could not open file: " .. tostring(filename))
  end
  local data = file:read("*all")
  file:close()
  if #data < 24 then
    error("Invalid PCAP file (too short): " .. tostring(filename))
  end
  local magic_be = su(">I4", data, 1)
  local magic_le = su("<I4", data, 1)
  local endian = nil
  local ts_div = 1e6
  if magic_be == 0xa1b2c3d4 then
    endian = ">"
  elseif magic_le == 0xa1b2c3d4 then
    endian = "<"
  elseif magic_be == 0xa1b23c4d then
    endian = ">"
    ts_div = 1e9
  elseif magic_le == 0xa1b23c4d then
    endian = "<"
    ts_div = 1e9
  else
    error("Unsupported PCAP magic: 0x" .. tostring(string.format("%08x", magic_be)))
  end
  local packets = { }
  local offset = 25
  while offset + 15 <= #data do
    local ts_sec, ts_frac, incl_len, orig_len = su(tostring(endian) .. "I4I4I4I4", data, offset)
    offset = offset + 16
    if incl_len < 0 or offset + incl_len - 1 > #data then
      break
    end
    local packet_data = data:sub(offset, offset + incl_len - 1)
    offset = offset + incl_len
    packets[#packets + 1] = {
      timestamp = ts_sec + (ts_frac / ts_div),
      captured_len = incl_len,
      original_len = orig_len,
      packet_data = packet_data
    }
  end
  return packets
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
  local endian = nil
  while offset + 11 <= #data do
    local block_type_le = su("<I4", data, offset)
    local block_type_be = su(">I4", data, offset)
    local block_type = block_type_le
    if block_type_le == 0x0A0D0D0A or block_type_be == 0x0A0D0D0A then
      local bom_le = su("<I4", data, offset + 8)
      local bom_be = su(">I4", data, offset + 8)
      if bom_le == 0x1A2B3C4D then
        endian = "<"
      elseif bom_be == 0x1A2B3C4D then
        endian = ">"
      else
        error("Invalid SHB byte-order magic in " .. tostring(filename))
      end
      block_type = 0x0A0D0D0A
    end
    if not (endian) then
      error("PCAPNG section header missing before offset " .. tostring(offset))
    end
    local block_len = su(tostring(endian) .. "I4", data, offset + 4)
    if block_len < 12 or offset + block_len - 1 > #data then
      break
    end
    if block_type == 0x00000001 then
      local linktype = su(tostring(endian) .. "I2", data, offset + 8)
      interfaces[#interfaces + 1] = {
        linktype = linktype
      }
    elseif block_type == 0x00000006 then
      local interface_id, timestamp_high, timestamp_low, captured_len, original_len = su(tostring(endian) .. "I4I4I4I4I4", data, offset + 8)
      local packet_start = offset + 28
      local packet_end = packet_start + captured_len - 1
      if packet_end <= #data then
        packets[#packets + 1] = {
          interface_id = interface_id,
          timestamp_high = timestamp_high,
          timestamp_low = timestamp_low,
          captured_len = captured_len,
          original_len = original_len,
          timestamp = timestamp_high * 2 ^ 32 + timestamp_low,
          packet_data = data:sub(packet_start, packet_end),
          interface = interfaces[interface_id + 1]
        }
      end
    end
    offset = offset + block_len
  end
  return packets
end
local filter_quic_packets
filter_quic_packets = function(packets)
  local quic_packets = { }
  local quic_ports = {
    [443] = true,
    [80] = true,
    [8443] = true,
    [4433] = true
  }
  for i, packet in ipairs(packets) do
    local _continue_0 = false
    repeat
      local eth_frame, l3_offset = eth.parse(packet.packet_data)
      if not (eth_frame) then
        _continue_0 = true
        break
      end
      local ip_pkt, l4_offset = ip.parse(packet.packet_data, l3_offset)
      if not (ip_pkt and ip_pkt.protocol == ip.proto.UDP) then
        _continue_0 = true
        break
      end
      local udp_dgram, l7_offset = udp.parse(packet.packet_data, l4_offset)
      if not (udp_dgram and (quic_ports[udp_dgram.spt] or quic_ports[udp_dgram.dpt])) then
        _continue_0 = true
        break
      end
      local quic_pkt, _ = quic_mod.parse(packet.packet_data, l7_offset)
      if not (quic_pkt) then
        _continue_0 = true
        break
      end
      quic_packets[#quic_packets + 1] = {
        packet_num = i,
        timestamp = packet.timestamp,
        eth_frame = eth_frame,
        ip_pkt = ip_pkt,
        udp_dgram = udp_dgram,
        quic_pkt = quic_pkt,
        raw_data = packet.packet_data,
        quic_offset = l7_offset
      }
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return quic_packets
end
local load_quic_packets
load_quic_packets = function(filename)
  if filename:lower():match("%.pcapng$") then
    return filter_quic_packets(parse_pcapng(filename))
  end
  if filename:lower():match("%.pcap$") then
    return filter_quic_packets(parse_pcap(filename))
  end
  local ok_pcapng, pcapng_or_err = pcall(function()
    return filter_quic_packets(parse_pcapng(filename))
  end)
  if ok_pcapng then
    return pcapng_or_err
  end
  local ok_pcap, pcap_or_err = pcall(function()
    return filter_quic_packets(parse_pcap(filename))
  end)
  if ok_pcap then
    return pcap_or_err
  end
  return error("Could not parse capture as PCAPNG or PCAP: " .. tostring(filename))
end
local pcap_file = arg and arg[1]
if not (pcap_file) then
  print("Usage: " .. tostring(arg and arg[0] or 'parse_real_quic.moon') .. " /path/to/capture.(pcap|pcapng)")
  os.exit(1)
end
local quic_packets = load_quic_packets(pcap_file)
if #quic_packets == 0 then
  print("ERROR: No QUIC packets found in " .. tostring(pcap_file))
  os.exit(1)
end
local pkt = nil
for _index_0 = 1, #quic_packets do
  local candidate = quic_packets[_index_0]
  local q = candidate.quic_pkt
  if q and q.long_header and q.dst_connection_id and #q.dst_connection_id > 0 then
    pkt = candidate
    break
  end
end
pkt = pkt or quic_packets[1]
local e = pkt.eth_frame
local ip_pkt = pkt.ip_pkt
local u = pkt.udp_dgram
local q = pkt.quic_pkt
local off3 = pkt.quic_offset
local frame = pkt.raw_data
if not (e and ip_pkt and u and q and off3 and frame) then
  print("ERROR: Failed to extract a fully parsed QUIC packet from " .. tostring(pcap_file))
  os.exit(1)
end
if not (q.pn_off) then
  print("ERROR: QUIC packet does not contain packet number offset (pn_off)")
  os.exit(1)
end
local pn_off_quic = q.pn_off - off3 + 1
print("")
print(string.rep("=", 80))
print("QUIC Packet Parser - " .. tostring(pcap_file))
print(string.rep("=", 80))
print("")
print("Selected packet: #" .. tostring(pkt.packet_num or 1))
print("")
print("Layer 2 (Ethernet):")
print("  src MAC: " .. tostring(bin2hex(e.src)))
print("  dst MAC: " .. tostring(bin2hex(e.dst)))
print("")
print("Layer 3 (IP):")
print("  src: " .. tostring(ip.ip2s(ip_pkt.src)))
print("  dst: " .. tostring(ip.ip2s(ip_pkt.dst)))
print("")
print("Layer 4 (UDP):")
print("  src port: " .. tostring(u.spt))
print("  dst port: " .. tostring(u.dpt))
print("")
print("Layer 7 (QUIC):")
print("  long header: " .. tostring(tostring(q.long_header)))
print(string.format("  version: 0x%08x", q.version or 0))
print("  DCID: " .. tostring(q.dst_connection_id and bin2hex(q.dst_connection_id) or '<none>'))
print("  packet length: " .. tostring(q.pkt_length or #frame - off3 + 1) .. " bytes")
print("")
print("RFC 9001 Decryption Pipeline:")
local dcid = q.dst_connection_id
if dcid and #dcid > 0 then
  print("  ✓ Keys derived from DCID")
  local ok_session, session_or_err = pcall(quic_session.new)
  if not (ok_session and session_or_err) then
    print("  ⚠ Crypto backend not available")
  else
    local session = session_or_err
    print("  ✓ Crypto backend loaded")
    local pushed = 0
    local decrypted = 0
    local last_err = nil
    local sni = nil
    for _index_0 = 1, #quic_packets do
      local _continue_0 = false
      repeat
        local quic_candidate = quic_packets[_index_0]
        local qh = quic_candidate.quic_pkt
        if not (qh and qh.long_header and qh.pkt_type == 0x00) then
          _continue_0 = true
          break
        end
        if not (qh.dst_connection_id == dcid) then
          _continue_0 = true
          break
        end
        local quic_bytes = quic_candidate.raw_data:sub(quic_candidate.quic_offset)
        local ok_push, err_push = session:push(quic_bytes)
        pushed = pushed + 1
        if ok_push then
          decrypted = decrypted + 1
          sni = session:sni()
          if sni then
            print("  ✓ Header protection removed")
            print("  ✓ Payload decrypted (stream reassembly across " .. tostring(decrypted) .. " Initial packets)")
            print("  ✓ SNI extracted: " .. tostring(sni))
            break
          end
        else
          last_err = err_push
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
    if not (sni) then
      if decrypted > 0 then
        print("  ✓ Header protection removed")
        print("  ✓ Payload decrypted")
        print("  ℹ SNI not found in payload")
      else
        print("  ✗ Decryption failed: " .. tostring(last_err or 'no decryptable Initial packet found'))
      end
    end
  end
else
  print("  ✗ DCID not found")
end
print("")
print(string.rep("=", 80))
print("✓ Parsing complete")
print(string.rep("=", 80))
return print("")
