local util = require("ipparse.lib.util")
local test
test = util.test
local pack
pack = require("ipparse.lib.pack_compat").pack
local pcap = require("ipparse.lib.pcap")
local make_shb
make_shb = function()
  return pack("<I4I4I4I2I2I8I4", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, 0, 28)
end
local make_idb
make_idb = function()
  return pack("<I4I4I2I2I4I4", 1, 20, 1, 0, 65535, 20)
end
local make_epb
make_epb = function(ts_hi, ts_lo, payload)
  local block_len = 28 + #payload + 4
  return pack("<I4I4I4I4I4I4I4", 6, block_len, 0, ts_hi, ts_lo, #payload, #payload) .. payload .. pack("<I4", block_len)
end
test("pcap: valid pcapng yields one Ethernet packet", function()
  local data = make_shb() .. make_idb() .. make_epb(0, 0, "\001\002\003\004")
  local packets = pcap.parse_pcapng_data(data)
  assert(#packets == 1, "packets: " .. tostring(#packets))
  assert(packets[1].packet_data == "\001\002\003\004", "payload mismatch")
  return assert(packets[1].interface.linktype_name == "ETHERNET", "linktype: " .. tostring(packets[1].interface.linktype_name))
end)
test("pcap: unknown block with zero length terminates", function()
  local data = make_shb() .. pack("<I4I4", 0xDEADBEEF, 0) .. make_idb()
  local packets = pcap.parse_pcapng_data(data)
  return assert(#packets == 0, "packets: " .. tostring(#packets))
end)
test("pcap: EPB with captured_len beyond block is skipped", function()
  local block_len = 36
  local header = pack("<I4I4I4I4I4I4I4", 6, block_len, 0, 0, 0, 100, 100)
  local data = make_shb() .. make_idb() .. header .. "\001\002\003\004" .. pack("<I4", block_len)
  local packets = pcap.parse_pcapng_data(data)
  return assert(#packets == 0, "packets: " .. tostring(#packets))
end)
test("pcap: truncated block at end terminates", function()
  local epb = make_epb(0, 0, "\001\002\003\004")
  local data = make_shb() .. make_idb() .. epb:sub(1, 20)
  local packets = pcap.parse_pcapng_data(data)
  return assert(#packets == 0, "packets: " .. tostring(#packets))
end)
test("pcap: 64-bit timestamp keeps high word", function()
  local data = make_shb() .. make_idb() .. make_epb(1, 2, "\001\002\003\004")
  local packets = pcap.parse_pcapng_data(data)
  assert(#packets == 1, "packets: " .. tostring(#packets))
  return assert(packets[1].timestamp == 4294967298, "timestamp: " .. tostring(packets[1].timestamp))
end)
local eth = require("ipparse.l2.ethernet")
local ip4 = require("ipparse.l3.ip4")
local udp = require("ipparse.l4.udp")
local make_quic_frame
make_quic_frame = function(quic_data, sport, dport, protocol)
  protocol = protocol or 17
  local udp_pkt = udp.pack(udp.new({
    spt = sport,
    dpt = dport,
    checksum = 0,
    data = quic_data
  }))
  local ip_pkt = ip4.pack(ip4.new({
    src = "\010\000\000\001",
    dst = "\010\000\000\002",
    protocol = protocol,
    data = udp_pkt
  }))
  return pack("c6 c6 >H", "\000\001\002\003\004\005", "\006\007\008\009\010\011", 0x0800) .. ip_pkt
end
local make_quic_long
make_quic_long = function(byte1)
  return pack(">B I4 s1 s1", byte1, 0x00000001, string.rep("\001", 8), "")
end
test("pcap: filter_quic_packets keeps QUIC on port 443", function()
  local frame = make_quic_frame(make_quic_long(0xB0), 12345, 443)
  local res = pcap.filter_quic_packets({
    {
      packet_data = frame,
      timestamp = 7
    }
  })
  assert(#res == 1, "expected 1 QUIC packet, got " .. tostring(#res))
  assert(res[1].udp_dgram.dpt == 443, "destination port mismatch")
  assert(res[1].quic_pkt.long_header == true, "expected a long header")
  assert(res[1].timestamp == 7, "timestamp should be forwarded")
  return assert(res[1].packet_num == 1, "packet_num should be 1")
end)
test("pcap: filter_quic_packets ignores non-QUIC ports", function()
  local frame = make_quic_frame(make_quic_long(0xB0), 12345, 9999)
  local res = pcap.filter_quic_packets({
    {
      packet_data = frame
    }
  })
  return assert(#res == 0, "expected no QUIC packet, got " .. tostring(#res))
end)
test("pcap: filter_quic_packets ignores non-UDP traffic", function()
  local frame = make_quic_frame(make_quic_long(0xB0), 12345, 443, 6)
  local res = pcap.filter_quic_packets({
    {
      packet_data = frame
    }
  })
  return assert(#res == 0, "expected no QUIC packet, got " .. tostring(#res))
end)
test("pcap: filter_quic_packets ignores too-short frames", function()
  local res = pcap.filter_quic_packets({
    {
      packet_data = "\001\002"
    }
  })
  return assert(#res == 0, "expected no QUIC packet, got " .. tostring(#res))
end)
test("pcap: filter_quic_packets handles short headers and verbose logging", function()
  local frame = make_quic_frame("\000\000\000\000\000\000\000\000\000", 443, 12345)
  local original_print = _G.print
  local lines = { }
  _G.print = function(msg)
    lines[#lines + 1] = msg
  end
  pcap.verbose = true
  local ok, res = pcall(pcap.filter_quic_packets, {
    {
      packet_data = frame
    }
  })
  pcap.verbose = false
  _G.print = original_print
  assert(ok, "filter should not raise: " .. tostring(res))
  assert(#res == 1, "expected 1 QUIC packet, got " .. tostring(#res))
  return assert(#lines > 0, "expected verbose log lines")
end)
test("pcap: parse_pcapng reads a real temporary file", function()
  local data = make_shb() .. make_idb() .. make_epb(0, 0, "\001\002\003\004")
  local fname = os.tmpname()
  local f = io.open(fname, "wb")
  f:write(data)
  f:close()
  local ok, packets = pcall(pcap.parse_pcapng, fname)
  os.remove(fname)
  assert(ok, "parse_pcapng raised: " .. tostring(packets))
  assert(#packets == 1, "expected 1 packet, got " .. tostring(#packets))
  return assert(packets[1].packet_data == "\001\002\003\004", "payload mismatch")
end)
test("pcap: parse_pcapng raises on a missing file", function()
  local ok, err = pcall(pcap.parse_pcapng, "/nonexistent/definitely-missing.pcapng")
  assert(not ok, "expected an error for a missing file")
  return assert(tostring(err):find("Could not open", 1, true), "error should mention 'Could not open', got " .. tostring(err))
end)
test("pcap: parse_pcapng_data logs when verbose", function()
  local data = make_shb() .. make_idb() .. make_epb(0, 0, "\001\002\003\004")
  local original_print = _G.print
  local lines = { }
  _G.print = function(msg)
    lines[#lines + 1] = msg
  end
  pcap.verbose = true
  local ok, packets = pcall(pcap.parse_pcapng_data, data)
  pcap.verbose = false
  _G.print = original_print
  assert(ok, "parse_pcapng_data raised: " .. tostring(packets))
  assert(#packets == 1, "expected 1 packet, got " .. tostring(#packets))
  return assert(#lines > 0, "expected verbose log lines")
end)
local make_shb_be
make_shb_be = function()
  return pack(">I4I4I4I2I2I8I4", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, 0, 28)
end
local make_idb_be
make_idb_be = function()
  return pack(">I4I4I2I2I4I4", 1, 20, 1, 0, 65535, 20)
end
local make_epb_be
make_epb_be = function(payload)
  local block_len = 28 + #payload + 4
  return pack(">I4I4I4I4I4I4I4", 6, block_len, 0, 0, 0, #payload, #payload) .. payload .. pack(">I4", block_len)
end
test("pcap: big-endian pcapng parses", function()
  local data = make_shb_be() .. make_idb_be() .. make_epb_be("\001\002\003\004")
  local packets = pcap.parse_pcapng_data(data)
  assert(#packets == 1, "expected 1 packet, got " .. tostring(#packets))
  assert(packets[1].packet_data == "\001\002\003\004", "payload mismatch")
  return assert(packets[1].endian == ">", "expected big-endian block")
end)
test("pcap: parse_quic_from_pcapng finds a QUIC packet in a file", function()
  local frame = make_quic_frame(make_quic_long(0xB0), 12345, 443)
  local pad = (4 - (#frame % 4)) % 4
  frame = frame .. string.rep("\000", pad)
  local data = make_shb() .. make_idb() .. make_epb(0, 0, frame)
  local fname = os.tmpname()
  local f = io.open(fname, "wb")
  f:write(data)
  f:close()
  local ok, res = pcall(pcap.parse_quic_from_pcapng, fname)
  os.remove(fname)
  assert(ok, "parse_quic_from_pcapng raised: " .. tostring(res))
  assert(#res == 1, "expected 1 QUIC packet, got " .. tostring(#res))
  return assert(res[1].udp_dgram.dpt == 443, "destination port mismatch")
end)
return util.summary("pcap")
