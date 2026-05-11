local util = require("ipparse.lib.util")
local test, summary
test, summary = util.test, util.summary
local su
su = require("ipparse.lib.pack_compat").unpack
local eth_mod = require("ipparse.l2.ethernet")
local ip_mod = require("ipparse.l3.ip")
local udp_mod = require("ipparse.l4.udp")
local quic_mod = require("ipparse.l4.quic")
local session_mod = require("ipparse.l7.quic.session")
local bin2hex
bin2hex = function(s)
  return s:gsub(".", function(c)
    return string.format("%02x", string.byte(c))
  end)
end
local EXPECTED = {
  dst_mac = "f2198cc26bb3",
  src_mac = "f2e9008a2acc",
  src_ip = "3ffa:e7fe:4375:16ed:e28f:4cff:fec8:91fa",
  dst_ip = "2485:ec87:7655:20de:0:0:0:8b",
  udp_spt = 35336,
  udp_dpt = 443,
  sni = "google.com"
}
local resolve_capture_path
resolve_capture_path = function()
  local candidates = {
    "ipparse/quic_google.pcapng",
    "quic_google.pcapng",
    "/lib/modules/lua/ipparse/quic_google.pcapng"
  }
  for _index_0 = 1, #candidates do
    local path = candidates[_index_0]
    local f = io.open(path, "rb")
    if f then
      f:close()
      return path
    end
  end
  return nil, "quic_google.pcapng not found (tried: " .. tostring(table.concat(candidates, ', ')) .. ")"
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
local load_flow
load_flow = function(capture_path)
  local packets = parse_pcapng(capture_path)
  assert(#packets > 0, "empty pcapng capture: " .. tostring(capture_path))
  local first = nil
  local initial_dcid = nil
  local initial_datagrams = { }
  for _index_0 = 1, #packets do
    local _continue_0 = false
    repeat
      local packet = packets[_index_0]
      local e, l3_off = eth_mod.parse(packet.packet_data, 1)
      if not (e) then
        _continue_0 = true
        break
      end
      local ip_pkt, l4_off = ip_mod.parse(packet.packet_data, l3_off)
      if not (ip_pkt and ip_pkt.protocol == ip_mod.proto.UDP) then
        _continue_0 = true
        break
      end
      local udp_dgram, l7_off = udp_mod.parse(packet.packet_data, l4_off)
      if not (udp_dgram) then
        _continue_0 = true
        break
      end
      local q, _ = quic_mod.parse(packet.packet_data, l7_off)
      if not (q and q.long_header and q.pkt_type == 0x00 and q.dst_connection_id and #q.dst_connection_id > 0) then
        _continue_0 = true
        break
      end
      if not first then
        first = {
          e = e,
          ip_pkt = ip_pkt,
          udp_dgram = udp_dgram,
          q = q
        }
        initial_dcid = q.dst_connection_id
      end
      if q.dst_connection_id == initial_dcid then
        initial_datagrams[#initial_datagrams + 1] = packet.packet_data:sub(l7_off)
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  assert(first ~= nil, "no QUIC Initial packet found in " .. tostring(capture_path))
  assert(#initial_datagrams > 0, "no client Initial datagrams found for selected DCID")
  return {
    first = first,
    initial_datagrams = initial_datagrams
  }
end
local capture_path, path_err = resolve_capture_path()
local flow = nil
local flow_err = nil
if capture_path then
  local ok, flow_or_err = pcall(function()
    return load_flow(capture_path)
  end)
  if ok then
    flow = flow_or_err
  else
    flow_err = flow_or_err
  end
end
local run_backend
run_backend = function(label, backend_mod)
  local ok_backend, backend_or_err = pcall(require, backend_mod)
  if not (ok_backend and backend_or_err) then
    test("quic.google.capture: " .. tostring(label) .. " backend not available (skipped)", function()
      return true
    end)
    return 
  end
  return test("quic.google.capture: " .. tostring(label) .. " backend parses L2->SNI", function()
    assert(capture_path ~= nil, path_err)
    assert(flow ~= nil, tostring(flow_err))
    local f = flow.first
    assert(bin2hex(f.e.dst) == EXPECTED.dst_mac, "dst mac mismatch: " .. tostring(bin2hex(f.e.dst)))
    assert(bin2hex(f.e.src) == EXPECTED.src_mac, "src mac mismatch: " .. tostring(bin2hex(f.e.src)))
    assert(ip_mod.ip2s(f.ip_pkt.src) == EXPECTED.src_ip, "src ip mismatch: " .. tostring(ip_mod.ip2s(f.ip_pkt.src)))
    assert(ip_mod.ip2s(f.ip_pkt.dst) == EXPECTED.dst_ip, "dst ip mismatch: " .. tostring(ip_mod.ip2s(f.ip_pkt.dst)))
    assert(f.udp_dgram.spt == EXPECTED.udp_spt, "udp source port mismatch: " .. tostring(f.udp_dgram.spt))
    assert(f.udp_dgram.dpt == EXPECTED.udp_dpt, "udp destination port mismatch: " .. tostring(f.udp_dgram.dpt))
    assert(f.q.long_header == true, "expected QUIC long header")
    assert(f.q.pkt_type == 0x00, "expected QUIC Initial packet")
    local sess = session_mod.new({
      backend = backend_or_err
    })
    local _list_0 = flow.initial_datagrams
    for _index_0 = 1, #_list_0 do
      local quic_packet = _list_0[_index_0]
      local ok_push, err_push = sess:push(quic_packet)
      assert(ok_push, tostring(label) .. ": " .. tostring(err_push))
      if sess:sni() then
        break
      end
    end
    return assert(sess:sni() == EXPECTED.sni, "expected SNI " .. tostring(EXPECTED.sni) .. ", got " .. tostring(tostring(sess:sni())))
  end)
end
run_backend("lunatik", "ipparse.lib.crypto.backend.lunatik")
run_backend("wolfssl", "ipparse.lib.crypto.backend.ffi_wolfssl")
run_backend("mbedtls", "ipparse.lib.crypto.backend.ffi_mbedtls")
run_backend("openssl", "ipparse.lib.crypto.backend.ffi_openssl")
return summary("l7.quic.google_capture_backends")
