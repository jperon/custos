local bit = require("bit")
local ffi = require("ffi")
package.loaded["ffi_defs"] = {
  ffi = ffi,
  libc = ffi.C,
  libnfq = { },
  libnft = { }
}
pcall(function()
  return ffi.cdef([[    const char* inet_ntop(int af, const void *src, char *dst, unsigned int size);
  ]])
end)
local PROTO_TCP = 6
local PROTO_UDP = 17
local AF_INET = 2
local AF_INET6 = 10
local DNS_PORT = 53
local DOCKER_MODE = false
local ALLOWED_DOMAINS = { }
local IPC_MSG_SIZE = 27
local IPC_PENDING_TTL = 5
local CLIENT_EXPIRY = 300
package.loaded["config"] = {
  PROTO_TCP = PROTO_TCP,
  PROTO_UDP = PROTO_UDP,
  AF_INET = AF_INET,
  AF_INET6 = AF_INET6,
  DNS_PORT = DNS_PORT,
  DOCKER_MODE = DOCKER_MODE,
  ALLOWED_DOMAINS = ALLOWED_DOMAINS,
  IPC_MSG_SIZE = IPC_MSG_SIZE,
  IPC_PENDING_TTL = IPC_PENDING_TTL,
  CLIENT_EXPIRY = CLIENT_EXPIRY
}
local passed, failed = 0, 0
local eq
eq = function(a, b)
  if type(a) == "table" and type(b) == "table" then
    for k, v in pairs(b) do
      if a[k] ~= v then
        return false
      end
    end
    for k in pairs(a) do
      if b[k] == nil then
        return false
      end
    end
    return true
  end
  return a == b
end
local test
test = function(name, fn)
  local ok, err = pcall(fn)
  if ok then
    passed = passed + 1
    return io.write(string.format("  OK   %s\n", name))
  else
    failed = failed + 1
    return io.write(string.format("  FAIL %s\n       %s\n", name, tostring(err)))
  end
end
local assert_eq
assert_eq = function(got, expected, msg)
  if not eq(got, expected) then
    return error(string.format("%s\n       got:      %s\n       expected: %s", msg or "", tostring(got), tostring(expected)), 2)
  end
end
local make_dns
make_dns = function(qname_encoded, qtype, is_response, txid)
  txid = txid or 0x1234
  qtype = qtype or 1
  local flags_hi = is_response and 0x81 or 0x01
  local flags_lo = 0x00
  local hdr = string.char(bit.rshift(bit.band(txid, 0xFF00), 8), bit.band(txid, 0xFF), flags_hi, flags_lo, 0, 1, 0, 0, 0, 0, 0, 0)
  local qsection = qname_encoded .. string.char(0, qtype, 0, 1)
  return hdr .. qsection
end
local make_ipv4_udp_dns
make_ipv4_udp_dns = function(src_ip, dst_ip, src_port, dst_port, dns_payload)
  local total_len = 20 + 8 + #dns_payload
  local ihl_ver = 0x45
  local ip = string.char(ihl_ver, 0, bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF), 0, 1, 0, 0, 64, PROTO_UDP, 0, 0)
  local ip4bytes
  ip4bytes = function(s)
    local a, b, c, d = s:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    return string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
  end
  ip = ip .. ip4bytes(src_ip) .. ip4bytes(dst_ip)
  local udp_len = 8 + #dns_payload
  local udp = string.char(bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF), bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF), bit.rshift(bit.band(udp_len, 0xFF00), 8), bit.band(udp_len, 0xFF), 0, 0)
  return ip .. udp .. dns_payload
end
local make_ipv4_tcp_dns
make_ipv4_tcp_dns = function(src_ip, dst_ip, src_port, dst_port, dns_payload)
  local dns_len = #dns_payload
  local tcp_payload = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF)) .. dns_payload
  local total_len = 20 + 20 + #tcp_payload
  local ihl_ver = 0x45
  local ip = string.char(ihl_ver, 0, bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF), 0, 1, 0, 0, 64, PROTO_TCP, 0, 0)
  local ip4bytes
  ip4bytes = function(s)
    local a, b, c, d = s:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    return string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
  end
  ip = ip .. ip4bytes(src_ip) .. ip4bytes(dst_ip)
  local tcp = string.char(bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF), bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF), 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0x72, 0x10, 0, 0, 0, 0)
  return ip .. tcp .. tcp_payload
end
local make_ipv6_udp_dns
make_ipv6_udp_dns = function(src_ip6, dst_ip6, src_port, dst_port, dns_payload)
  local udp_len = 8 + #dns_payload
  local pay_len = udp_len
  local ip6 = string.char(0x60, 0, 0, 0, bit.rshift(bit.band(pay_len, 0xFF00), 8), bit.band(pay_len, 0xFF), 17, 64) .. src_ip6 .. dst_ip6
  local udp = string.char(bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF), bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF), bit.rshift(bit.band(udp_len, 0xFF00), 8), bit.band(udp_len, 0xFF), 0, 0)
  return ip6 .. udp .. dns_payload
end
local make_ipv6_ext_udp_dns
make_ipv6_ext_udp_dns = function(src_ip6, dst_ip6, src_port, dst_port, dns_payload, first_nh, ext_raw)
  local udp_len = 8 + #dns_payload
  local pay_len = #ext_raw + udp_len
  local ip6 = string.char(0x60, 0, 0, 0, bit.rshift(bit.band(pay_len, 0xFF00), 8), bit.band(pay_len, 0xFF), first_nh, 64) .. src_ip6 .. dst_ip6
  local udp = string.char(bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF), bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF), bit.rshift(bit.band(udp_len, 0xFF00), 8), bit.band(udp_len, 0xFF), 0, 0)
  return ip6 .. ext_raw .. udp .. dns_payload
end
local m_ndpi = dofile("lua/parse/ndpi.lua")
local parse_packet = m_ndpi.parse_packet
local get_flow = m_ndpi.get_flow
local purge_flows = m_ndpi.purge_flows
test("parse_packet — UDP DNS minimal", function()
  local dns = make_dns("\3www\6github\3com\0", 1, false)
  local raw = make_ipv4_udp_dns("192.168.1.42", "8.8.8.8", 54321, 53, dns)
  local pkt = parse_packet(raw)
  assert(pkt, "parse_packet nil")
  assert_eq(pkt.l4.proto, "udp", "proto")
  assert_eq(pkt.dns.txid, 0x1234, "txid")
  return assert_eq(pkt.questions[1].qname, "www.github.com", "qname")
end)
test("parse_packet — TCP DNS minimal", function()
  local dns = make_dns("\3www\6github\3com\0", 1, false)
  local raw = make_ipv4_tcp_dns("192.168.1.42", "8.8.8.8", 54321, 53, dns)
  local pkt = parse_packet(raw)
  assert(pkt, "parse_packet nil")
  assert_eq(pkt.l4.proto, "tcp", "proto")
  assert_eq(pkt.dns.txid, 0x1234, "txid")
  return assert_eq(pkt.questions[1].qname, "www.github.com", "qname")
end)
test("parse_packet — TCP DNS too short (no length prefix)", function()
  local raw = make_ipv4_tcp_dns("192.168.1.42", "8.8.8.8", 54322, 53, "")
  raw = raw:sub(1, #raw - 1)
  local pkt = parse_packet(raw)
  return assert_eq(pkt, nil, "should be nil if payload < 14B")
end)
test("parse_packet — IPv6 + Hop-by-Hop (type 0) + UDP DNS", function()
  local hbh = string.char(17, 0, 0, 0, 0, 0, 0, 0)
  local dns = make_dns("\3www\6github\3com\0", 1, false)
  local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  local raw = make_ipv6_ext_udp_dns(src6, dst6, 54321, 53, dns, 0, hbh)
  local pkt = parse_packet(raw)
  assert(pkt, "parse_packet nil with Hop-by-Hop")
  assert_eq(pkt.ip.version, 6, "version=6")
  assert_eq(pkt.ip.ihl, 48, "ihl=48 (40 + 8 ext)")
  assert_eq(pkt.l4.proto, "udp", "proto=udp")
  assert_eq(pkt.dns.txid, 0x1234, "txid")
  return assert_eq(pkt.questions[1].qname, "www.github.com", "qname")
end)
test("parse_packet — IPv6 + Routing (type 43) + UDP DNS", function()
  local rh = string.char(17, 0, 0, 0, 0, 0, 0, 0)
  local dns = make_dns("\3www\6github\3com\0", 1, false)
  local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  local raw = make_ipv6_ext_udp_dns(src6, dst6, 54321, 53, dns, 43, rh)
  local pkt = parse_packet(raw)
  assert(pkt, "parse_packet nil with Routing header")
  assert_eq(pkt.ip.ihl, 48, "ihl=48")
  assert_eq(pkt.l4.proto, "udp", "proto=udp")
  return assert_eq(pkt.questions[1].qname, "www.github.com", "qname")
end)
test("parse_packet — IPv6 + Fragment (type 44) + UDP DNS", function()
  local fh = string.char(17, 0, 0, 0, 0, 0, 0, 1)
  local dns = make_dns("\3www\6github\3com\0", 1, false)
  local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  local raw = make_ipv6_ext_udp_dns(src6, dst6, 54321, 53, dns, 44, fh)
  local pkt = parse_packet(raw)
  assert(pkt, "parse_packet nil with Fragment header")
  assert_eq(pkt.ip.ihl, 48, "ihl=48")
  assert_eq(pkt.l4.proto, "udp", "proto=udp")
  return assert_eq(pkt.questions[1].qname, "www.github.com", "qname")
end)
test("parse_packet — IPv6 + Hop-by-Hop + Routing (chained) + UDP DNS", function()
  local hbh = string.char(43, 0, 0, 0, 0, 0, 0, 0)
  local rh = string.char(17, 0, 0, 0, 0, 0, 0, 0)
  local dns = make_dns("\3www\6github\3com\0", 1, false)
  local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  local raw = make_ipv6_ext_udp_dns(src6, dst6, 54321, 53, dns, 0, hbh .. rh)
  local pkt = parse_packet(raw)
  assert(pkt, "parse_packet nil with chained ext headers")
  assert_eq(pkt.ip.ihl, 56, "ihl=56 (40 + 8 + 8)")
  assert_eq(pkt.l4.proto, "udp", "proto=udp")
  assert_eq(pkt.questions[1].qname, "www.github.com", "qname")
  dns = make_dns("\3www\6github\3com\0", 1, false)
  raw = make_ipv4_udp_dns("192.168.1.42", "8.8.8.8", 54321, 53, dns)
  pkt = parse_packet(raw)
  return true
end)
test("patch_and_checksum — TCP response", function()
  local qname_enc = "\6github\3com\0"
  local txid = 0x5678
  local hdr = string.char(0x56, 0x78, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  local question = qname_enc .. string.char(0, 1, 0, 1)
  local rr = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(1, 2, 3, 4)
  local dns_payload = hdr .. question .. rr
  local dns_len = #dns_payload
  local tcp_payload = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF)) .. dns_payload
  local raw = make_ipv4_tcp_dns("192.168.1.42", "8.8.8.8", 54323, 53, dns_payload)
  local pkt = parse_packet(raw)
  local answers = m_ndpi.parse_answers(raw, pkt)
  local patched = m_ndpi.patch_and_checksum(raw, pkt, answers, 60)
  local ttl_offset = 20 + 20 + 2 + 12 + 16 + 6 + 3
  return assert_eq(patched:byte(ttl_offset + 1), 60, "TTL patched to 60 in TCP packet")
end)
test("patch_and_checksum — TCP 2-segment reassembly patches TTL", function()
  local qname_enc = "\6github\3com\0"
  local hdr = string.char(0x9A, 0xBC, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  local question = qname_enc .. string.char(0, 1, 0, 1)
  local rr = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(5, 6, 7, 8)
  local dns_payload = hdr .. question .. rr
  local dns_len = #dns_payload
  local make_tcp_raw
  make_tcp_raw = function(src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_payload)
    local total_len = 20 + 20 + #tcp_payload
    local ip4bytes
    ip4bytes = function(s)
      local a, b, c, d = s:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
      return string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
    end
    local ip = string.char(0x45, 0, bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF), 0, 1, 0, 0, 64, PROTO_TCP, 0, 0) .. ip4bytes(src_ip) .. ip4bytes(dst_ip)
    local tcp = string.char(bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF), bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF), bit.rshift(bit.band(tcp_seq, 0xFF000000), 24), bit.rshift(bit.band(tcp_seq, 0x00FF0000), 16), bit.rshift(bit.band(tcp_seq, 0x0000FF00), 8), bit.band(tcp_seq, 0xFF), 0, 0, 0, 0, 0x50, 0x18, 0x72, 0x10, 0, 0, 0, 0)
    return ip .. tcp .. tcp_payload
  end
  local src_ip, dst_ip, src_port, dst_port = "192.168.1.42", "8.8.8.8", 54324, 53
  local init_seq = 0x00ABCDEF
  local prefix = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF))
  local raw1 = make_tcp_raw(src_ip, dst_ip, src_port, dst_port, init_seq, prefix)
  local pkt1, status1 = parse_packet(raw1)
  assert_eq(pkt1, nil, "seg1 should return nil (incomplete)")
  assert_eq(status1, "buffering", "seg1 should signal buffering")
  local raw2 = make_tcp_raw(src_ip, dst_ip, src_port, dst_port, init_seq + 2, dns_payload)
  local pkt2, _ = parse_packet(raw2)
  assert(pkt2, "seg2 should complete the DNS message")
  assert_eq(pkt2.l4.proto, "tcp", "proto tcp")
  assert_eq(pkt2.dns.txid, 0x9ABC, "txid")
  assert_eq(pkt2.tcp_single_segment, false, "multi-segment: not single")
  assert((pkt2.tcp_init_seq ~= nil), "tcp_init_seq should be set")
  assert_eq(pkt2.tcp_init_seq, init_seq, "tcp_init_seq == init_seq of seg1")
  local answers2 = m_ndpi.parse_answers(raw2, pkt2)
  assert_eq(#answers2, 1, "1 answer expected")
  local patched2 = m_ndpi.patch_and_checksum(raw2, pkt2, answers2, 60)
  local expected_len = 20 + 20 + 2 + dns_len
  assert_eq(#patched2, expected_len, "coalesced packet size")
  local ttl_off2 = 20 + 20 + 2 + 12 + 16 + 6 + 3
  assert_eq(patched2:byte(ttl_off2 + 1), 60, "TTL patched to 60 in coalesced TCP packet")
  local seq_b0 = patched2:byte(20 + 4 + 1)
  local seq_b1 = patched2:byte(20 + 4 + 2)
  local seq_b2 = patched2:byte(20 + 4 + 3)
  local seq_b3 = patched2:byte(20 + 4 + 4)
  local got_seq = bit.bor(bit.lshift(seq_b0, 24), bit.lshift(seq_b1, 16), bit.lshift(seq_b2, 8), seq_b3)
  return assert_eq(got_seq, init_seq, "TCP seq field restored to init_seq")
end)
test("patch_and_checksum — TCP 2-segment CNAME+A patches all TTLs", function()
  local qname_enc = "\6github\3com\0"
  local hdr = string.char(0xBB, 0xCC, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0)
  local question = qname_enc .. string.char(0, 1, 0, 1)
  local cname_target = "\3www\6github\3com\0"
  local rr1 = "\xC0\x0C" .. string.char(0, 5, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 16) .. cname_target
  local rr2 = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(1, 2, 3, 4)
  local dns_payload = hdr .. question .. rr1 .. rr2
  local dns_len = #dns_payload
  assert_eq(dns_len, 72, "dns_payload size")
  local make_tcp_raw2
  make_tcp_raw2 = function(src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_payload)
    local total_len = 20 + 20 + #tcp_payload
    local ip4b
    ip4b = function(s)
      local a, b, c, d = s:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
      return string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
    end
    local ip = string.char(0x45, 0, bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF), 0, 1, 0, 0, 64, PROTO_TCP, 0, 0) .. ip4b(src_ip) .. ip4b(dst_ip)
    local tcp = string.char(bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF), bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF), bit.rshift(bit.band(tcp_seq, 0xFF000000), 24), bit.rshift(bit.band(tcp_seq, 0x00FF0000), 16), bit.rshift(bit.band(tcp_seq, 0x0000FF00), 8), bit.band(tcp_seq, 0xFF), 0, 0, 0, 0, 0x50, 0x18, 0x72, 0x10, 0, 0, 0, 0)
    return ip .. tcp .. tcp_payload
  end
  local src_ip, dst_ip, src_port, dst_port = "192.168.1.42", "8.8.8.8", 54325, 53
  local init_seq2 = 0x00112233
  local prefix = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF))
  local raw1 = make_tcp_raw2(src_ip, dst_ip, src_port, dst_port, init_seq2, prefix)
  local p1, s1 = parse_packet(raw1)
  assert_eq(p1, nil, "seg1 nil")
  assert_eq(s1, "buffering", "seg1 buffering")
  local raw2 = make_tcp_raw2(src_ip, dst_ip, src_port, dst_port, init_seq2 + 2, dns_payload)
  local pkt3, _ = parse_packet(raw2)
  assert(pkt3, "seg2 completes DNS")
  assert_eq(pkt3.dns.txid, 0xBBCC, "txid")
  assert_eq(pkt3.tcp_single_segment, false, "multi-segment")
  local ans3 = m_ndpi.parse_answers(raw2, pkt3)
  assert_eq(#ans3, 2, "2 answers (CNAME + A)")
  assert_eq(ans3[1].ttl, 300, "RR1 original TTL")
  assert_eq(ans3[2].ttl, 300, "RR2 original TTL")
  local patched3 = m_ndpi.patch_and_checksum(raw2, pkt3, ans3, 42)
  local base = 42
  assert_eq(patched3:byte(base + 34 + 3 + 1), 42, "RR1 (CNAME) TTL patched to 42")
  assert_eq(patched3:byte(base + 62 + 3 + 1), 42, "RR2 (A)     TTL patched to 42")
  assert_eq(patched3:byte(base + 34 + 0 + 1), 0, "RR1 TTL byte0 = 0")
  assert_eq(patched3:byte(base + 34 + 1 + 1), 0, "RR1 TTL byte1 = 0")
  assert_eq(patched3:byte(base + 34 + 2 + 1), 0, "RR1 TTL byte2 = 0")
  assert_eq(patched3:byte(base + 62 + 0 + 1), 0, "RR2 TTL byte0 = 0")
  assert_eq(patched3:byte(base + 62 + 1 + 1), 0, "RR2 TTL byte1 = 0")
  return assert_eq(patched3:byte(base + 62 + 2 + 1), 0, "RR2 TTL byte2 = 0")
end)
local m_ip = dofile("lua/parse/ip.lua")
local read_u8 = m_ip.read_u8
local read_u16 = m_ip.read_u16
local read_u32 = m_ip.read_u32
local format_ipv4 = m_ip.format_ipv4
local parse_ipv4 = m_ip.parse_ipv4
local parse_ipv6 = m_ip.parse_ipv6
test("read_u16 big-endian", function()
  local s = "\x12\x34\x56\x78"
  assert_eq(read_u16(s, 1), 0x1234, "offset 1")
  return assert_eq(read_u16(s, 3), 0x5678, "offset 3")
end)
test("read_u32 big-endian", function()
  local s = "\xDE\xAD\xBE\xEF"
  return assert_eq(read_u32(s, 1), 0xDEADBEEF, "u32")
end)
test("format_ipv4", function()
  local s = "\xC0\xA8\x01\x01"
  return assert_eq(format_ipv4(s, 1), "192.168.1.1", "format")
end)
test("parse_ipv4 — paquet UDP minimal", function()
  local dns = make_dns("\3www\6github\3com\0", 1, false)
  local raw = make_ipv4_udp_dns("192.168.1.42", "8.8.8.8", 54321, 53, dns)
  local ip_hdr = parse_ipv4(raw)
  assert(ip_hdr, "parse_ipv4 retourne nil")
  assert_eq(ip_hdr.version, 4, "version")
  assert_eq(ip_hdr.ihl, 20, "ihl")
  assert_eq(ip_hdr.protocol, 17, "proto UDP")
  assert_eq(ip_hdr.src_ip, "192.168.1.42", "src_ip")
  return assert_eq(ip_hdr.dst_ip, "8.8.8.8", "dst_ip")
end)
test("parse_ipv4 — paquet trop court → nil", function()
  return assert_eq(parse_ipv4("\x45\x00\x00"), nil, "trop court")
end)
test("parse_ipv6 — paquet UDP minimal", function()
  local dns = make_dns("\x06github\x03com\x00", 1, false)
  local src6 = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42"
  local dst6 = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  local raw = make_ipv6_udp_dns(src6, dst6, 54321, 53, dns)
  local ip_hdr = parse_ipv6(raw)
  assert(ip_hdr, "parse_ipv6 retourne nil")
  assert_eq(ip_hdr.version, 6, "version=6")
  assert_eq(ip_hdr.ihl, 40, "ihl=40 (pas d'ext headers)")
  assert_eq(ip_hdr.protocol, 17, "proto UDP")
  assert_eq(ip_hdr.src_ip, "2001:db8:0:0:0:0:0:42", "src_ip")
  assert_eq(ip_hdr.dst_ip, "2001:db8:0:0:0:0:0:1", "dst_ip")
  return assert((ip_hdr.src_ip_raw and #ip_hdr.src_ip_raw == 16), "src_ip_raw 16 octets")
end)
test("parse_ipv6 — Hop-by-Hop + UDP", function()
  local hbh = string.char(17, 0, 0, 0, 0, 0, 0, 0)
  local dns = make_dns("\x06github\x03com\x00", 1, false)
  local src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  local dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  local raw = make_ipv6_ext_udp_dns(src6, dst6, 54321, 53, dns, 0, hbh)
  local ip_hdr = parse_ipv6(raw)
  assert(ip_hdr, "parse_ipv6 nil avec Hop-by-Hop")
  assert_eq(ip_hdr.version, 6, "version=6")
  assert_eq(ip_hdr.ihl, 48, "ihl=48 (40+8)")
  assert_eq(ip_hdr.protocol, 17, "proto UDP")
  return assert((#ip_hdr.src_ip_raw == 16), "src_ip_raw 16 octets")
end)
io.write("\n── parse/dns ──\n")
package.loaded["parse/ip"] = dofile("lua/parse/ip.lua")
local m_dns = dofile("lua/parse/dns.lua")
local decode_name = m_dns.decode_name
local parse_dns = m_dns.parse_dns
local QTYPE = m_dns.QTYPE
local RCODE = m_dns.RCODE
local patch_ttl = m_dns.patch_ttl
local build_refused = m_dns.build_refused
test("decode_name — labels simples", function()
  local buf = "\3www\8facebook\3com\0"
  local name, consumed = decode_name(buf, 1)
  assert_eq(name, "www.facebook.com", "name")
  return assert_eq(consumed, #buf, "consumed")
end)
test("decode_name — pointeur de compression", function()
  local base = "\x03foo\x03bar\x00"
  local ptr = "\xC0\x00"
  local buf = base .. ptr
  local name, consumed = decode_name(buf, 10)
  assert_eq(name, "foo.bar", "compressed name")
  return assert_eq(consumed, 2, "consumed = 2 (juste le pointeur)")
end)
test("decode_name — protection boucle infinie", function()
  local buf = "\xC0\x02\xC0\x00"
  local name, consumed = decode_name(buf, 1)
  return assert_eq(name, nil, "boucle circulaire detectee → nil")
end)
test("parse_dns — question A www.github.com", function()
  local qname = "\3www\6github\3com\0"
  local dns_payload = make_dns(qname, QTYPE.A, false, 0xABCD)
  local parsed = parse_dns(dns_payload)
  assert(parsed, "parse_dns nil")
  assert_eq(parsed.hdr.txid, 0xABCD, "txid")
  assert_eq(parsed.hdr.is_response, false, "is_response")
  assert_eq(parsed.hdr.qdcount, 1, "qdcount")
  assert_eq(#parsed.questions, 1, "1 question")
  assert_eq(parsed.questions[1].qname, "www.github.com", "qname")
  return assert_eq(parsed.questions[1].qtype, QTYPE.A, "qtype A")
end)
test("parse_dns — réponse avec RR A", function()
  local qname_enc = "\6github\3com\0"
  local txid = 0x5678
  local hdr = string.char(0x56, 0x78, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  local question = qname_enc .. string.char(0, 1, 0, 1)
  local rr = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(1, 2, 3, 4)
  local dns_payload = hdr .. question .. rr
  local parsed = parse_dns(dns_payload)
  assert(parsed, "parse_dns nil")
  assert_eq(parsed.hdr.is_response, true, "is_response")
  assert_eq(parsed.hdr.ancount, 1, "ancount")
  assert_eq(#parsed.answers, 1, "1 answer")
  assert_eq(parsed.answers[1].rdata_str, "1.2.3.4", "rdata_str")
  assert_eq(parsed.answers[1].rtype, QTYPE.A, "rtype A")
  return assert_eq(parsed.answers[1].ttl, 300, "ttl original")
end)
test("build_refused -- header REFUSED + EDE OPT", function()
  local qname = "\8facebook\3com\0"
  local dns_buf = make_dns(qname, QTYPE.A, false, 0xBEEF)
  local dns_obj = parse_dns(dns_buf)
  assert(dns_obj, "parse_dns nil")
  local refused = build_refused(dns_obj, dns_buf)
  assert(refused, "build_refused nil")
  local resp = parse_dns(refused)
  assert(resp, "parse_dns sur la reponse REFUSED nil")
  assert_eq(resp.hdr.txid, 0xBEEF, "txid copié")
  assert_eq(resp.hdr.is_response, true, "QR=1")
  assert_eq(resp.hdr.rcode, RCODE.REFUSED, "RCODE=5 REFUSED")
  assert_eq(resp.hdr.qdcount, 1, "qdcount copié")
  assert_eq(resp.hdr.ancount, 0, "ancount=0")
  assert_eq(resp.hdr.arcount, 1, "arcount=1 EDNS OPT")
  assert_eq(#resp.questions, 1, "1 question copiée")
  return assert_eq(resp.questions[1].qname, "facebook.com", "qname copié")
end)
test("build_refused -- OPT RR EDE bytes", function()
  local qname = "\3foo\3com\0"
  local dns_buf = make_dns(qname, QTYPE.A, false, 0x1234)
  local dns_obj = parse_dns(dns_buf)
  local refused = build_refused(dns_obj, dns_buf)
  assert(refused, "build_refused nil")
  local q_len = #qname + 4
  local opt_start = 12 + q_len + 1
  local ede_n = #m_dns.EDE_EXTRA_TEXT
  local rdlen = 6 + ede_n
  local opt_len = 2 + ede_n
  assert_eq(refused:byte(opt_start), 0x00, "OPT NAME = root")
  assert_eq(refused:byte(opt_start + 1), 0x00, "OPT TYPE hi")
  assert_eq(refused:byte(opt_start + 2), 0x29, "OPT TYPE lo = 41")
  assert_eq(refused:byte(opt_start + 9), 0x00, "RDLEN hi")
  assert_eq(refused:byte(opt_start + 10), rdlen, "RDLEN lo = " .. tostring(rdlen))
  assert_eq(refused:byte(opt_start + 11), 0x00, "EDE opt-code hi")
  assert_eq(refused:byte(opt_start + 12), 0x0F, "EDE opt-code lo = 15")
  assert_eq(refused:byte(opt_start + 13), 0x00, "EDE opt-len hi")
  assert_eq(refused:byte(opt_start + 14), opt_len, "EDE opt-len lo = " .. tostring(opt_len))
  assert_eq(refused:byte(opt_start + 15), 0x00, "EDE info-code hi")
  assert_eq(refused:byte(opt_start + 16), 0x0F, "EDE info-code lo = 15 Filtered")
  local extra = refused:sub(opt_start + 17, opt_start + 16 + ede_n)
  return assert_eq(extra, m_dns.EDE_EXTRA_TEXT, "EDE extra-text = '" .. tostring(m_dns.EDE_EXTRA_TEXT) .. "'")
end)
test("patch_ttl — réécrit 4 octets TTL dans le buffer", function()
  local qname_enc = "\x06github\x03com\x00"
  local txid = 0x5678
  local hdr = string.char(0x56, 0x78, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  local question = qname_enc .. string.char(0, 1, 0, 1)
  local rr = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(1, 2, 3, 4)
  local dns_payload = hdr .. question .. rr
  local parsed = parse_dns(dns_payload)
  assert(parsed, "parse_dns nil")
  assert_eq(#parsed.answers, 1, "must have 1 answer")
  assert_eq(parsed.answers[1].ttl, 300, "ttl original = 300")
  local pkt_len = #dns_payload
  local buf = ffi.new("uint8_t[?]", pkt_len)
  ffi.copy(buf, dns_payload, pkt_len)
  patch_ttl(buf, parsed.answers, 0, 60)
  local ttl_off0 = parsed.answers[1].ttl_offset - 1
  assert_eq(buf[ttl_off0], 0x00, "TTL byte 0")
  assert_eq(buf[ttl_off0 + 1], 0x00, "TTL byte 1")
  assert_eq(buf[ttl_off0 + 2], 0x00, "TTL byte 2")
  return assert_eq(buf[ttl_off0 + 3], 60, "TTL byte 3 = 60")
end)
io.write("\n── parse/udp ──\n")
package.loaded["parse/ip"] = dofile("lua/parse/ip.lua")
local m_udp = dofile("lua/parse/udp.lua")
local parse_udp = m_udp.parse_udp
local checksum_udp = m_udp.checksum_udp
local pseudo_header_sum_v4 = m_udp.pseudo_header_sum_v4
local pseudo_header_sum_v6 = m_udp.pseudo_header_sum_v6
test("pseudo_header_sum_v4 — somme connue", function()
  local src = "\xC0\xA8\x01\x2A"
  local dst = "\x08\x08\x08\x08"
  local s = pseudo_header_sum_v4(src, dst, 100)
  local expected = 0xC0A8 + 0x012A + 0x0808 + 0x0808 + 17 + 100
  return assert_eq(s, expected, "somme pseudo-header v4")
end)
test("pseudo_header_sum_v6 -- 16 octets non tronques", function()
  local src = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  local dst = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
  local s = pseudo_header_sum_v6(src, dst, 60)
  local expected = 0x2DBA + 0x2DBB + 60 + 17
  return assert_eq(s, expected, "somme pseudo-header v6")
end)
test("checksum_udp IPv4 -- not zero", function()
  local dns = make_dns("\x03www\x06github\x03com\x00", 1, false)
  local raw = make_ipv4_udp_dns("192.168.1.42", "8.8.8.8", 54321, 53, dns)
  local ip_m = dofile("lua/parse/ip.lua")
  local udp_m = dofile("lua/parse/udp.lua")
  local ip_hdr = ip_m.parse_ipv4(raw)
  local udp_hdr = udp_m.parse_udp(raw, ip_hdr)
  local cksum = checksum_udp(raw, ip_hdr, udp_hdr)
  assert((cksum ~= 0), "checksum IPv4 non nul")
  return assert((cksum <= 0xFFFF), "checksum <= 0xFFFF")
end)
test("checksum_udp IPv6 -- non nul et different du checksum IPv4 meme payload", function()
  local dns = make_dns("\x06github\x03com\x00", 1, false)
  local src6 = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42"
  local dst6 = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  local raw6 = make_ipv6_udp_dns(src6, dst6, 54321, 53, dns)
  local raw4 = make_ipv4_udp_dns("192.168.1.42", "8.8.8.8", 54321, 53, dns)
  local ip_m = dofile("lua/parse/ip.lua")
  local udp_m = dofile("lua/parse/udp.lua")
  local ip6_hdr = ip_m.parse_ipv6(raw6)
  local udp6_hdr = udp_m.parse_udp(raw6, ip6_hdr)
  local ip4_hdr = ip_m.parse_ipv4(raw4)
  local udp4_hdr = udp_m.parse_udp(raw4, ip4_hdr)
  local ck6 = checksum_udp(raw6, ip6_hdr, udp6_hdr)
  local ck4 = checksum_udp(raw4, ip4_hdr, udp4_hdr)
  assert((ck6 ~= 0), "checksum IPv6 non nul")
  assert((ck6 <= 0xFFFF), "checksum IPv6 <= 0xFFFF")
  return assert((ck6 ~= ck4), "checksum IPv6 != checksum IPv4 (pseudo-headers differents)")
end)
io.write("\n── allowlist ──\n")
local make_is_allowed
make_is_allowed = function(domains)
  local set = { }
  for _, d in ipairs(domains) do
    set[d:lower()] = true
  end
  return function(qname)
    local name = qname:lower()
    if set[name] then
      return true
    end
    local pos = name:find(".", 1, true)
    while pos do
      local suffix = name:sub(pos + 1)
      if set[suffix] then
        return true
      end
      pos = name:find(".", pos + 1, true)
    end
    return false
  end
end
local allowed_list = {
  "github.com",
  "debian.org",
  "cloudflare.com",
  "local",
  "home.arpa"
}
local is_allowed = make_is_allowed(allowed_list)
local cases = {
  {
    "www.github.com",
    true
  },
  {
    "github.com",
    true
  },
  {
    "api.github.com",
    true
  },
  {
    "sub.api.github.com",
    true
  },
  {
    "notgithub.com",
    false
  },
  {
    "evil.com",
    false
  },
  {
    "www.evil.github.com.evil.com",
    false
  },
  {
    "debian.org",
    true
  },
  {
    "ftp.debian.org",
    true
  },
  {
    "ubuntu.com",
    false
  },
  {
    "myhost.local",
    true
  },
  {
    "gateway.home.arpa",
    true
  }
}
for _, c in ipairs(cases) do
  test(string.format("allowlist(%s) == %s", c[1], tostring(c[2])), function()
    return assert_eq(is_allowed(c[1]), c[2], c[1])
  end)
end
io.write("\n── ipc ──\n")
package.loaded["ipc"] = nil
package.loaded["log"] = {
  log_warn = function()
    return nil
  end,
  log_error = function()
    return nil
  end,
  log_info = function()
    return nil
  end,
  now = function()
    return os.time()
  end
}
local m_ipc = dofile("lua/ipc.lua")
local encode_msg = m_ipc.encode_msg
local decode_msg = m_ipc.decode_msg
local make_key = m_ipc.make_key
test("encode/decode IPv4 round-trip", function()
  local ip_raw = "\xC0\xA8\x01\x2A"
  local mac_raw = "\xAA\xBB\xCC\xDD\xEE\xFF"
  local txid = 0x1234
  local port = 54321
  local msg = encode_msg(txid, ip_raw, port, mac_raw)
  assert_eq(#msg, 27, "taille message = 27")
  local decoded = decode_msg(msg)
  assert(decoded, "decode_msg nil")
  assert_eq(decoded.txid, txid, "txid")
  assert_eq(decoded.src_port, port, "port")
  assert_eq(decoded.ip_str, "192.168.1.42", "ip_str")
  assert_eq(decoded.msg_type, 0x41, "type IPv4")
  return assert_eq(decoded.mac_str, "aa:bb:cc:dd:ee:ff", "mac_str")
end)
test("encode/decode IPv4 round-trip sans MAC (nil)", function()
  local ip_raw = "\xC0\xA8\x01\x2A"
  local msg = encode_msg(0x1234, ip_raw, 54321, nil)
  assert_eq(#msg, 27, "taille message = 27 meme sans MAC")
  local decoded = decode_msg(msg)
  assert(decoded, "decode_msg nil")
  return assert_eq(decoded.mac_str, "00:00:00:00:00:00", "mac zeros si nil")
end)
test("encode/decode IPv6 round-trip", function()
  local ip_raw = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  local mac_raw = "\x00\x11\x22\x33\x44\x55"
  local txid = 0xABCD
  local port = 5353
  local msg = encode_msg(txid, ip_raw, port, mac_raw)
  assert_eq(#msg, 27, "taille message = 27")
  local decoded = decode_msg(msg)
  assert(decoded, "decode_msg nil")
  assert_eq(decoded.txid, txid, "txid")
  assert_eq(decoded.src_port, port, "port")
  assert_eq(decoded.ip_str, "2001:db8::1", "ip_str")
  assert_eq(decoded.msg_type, 0x36, "type IPv6")
  return assert_eq(decoded.mac_str, "00:11:22:33:44:55", "mac_str")
end)
test("make_key — unicité", function()
  local k1 = make_key(0x1234, "192.168.1.1", 53)
  local k2 = make_key(0x1234, "192.168.1.2", 53)
  local k3 = make_key(0x5678, "192.168.1.1", 53)
  assert((k1 ~= k2), "ip différentes → clés différentes")
  return assert((k1 ~= k3), "txid différents → clés différentes")
end)
test("drain_pipe — lit IPC_MSG_SIZE=27 octets sans overflow", function()
  pcall(ffi.cdef, [[    int pipe2(int pipefd[2], int flags);
    int fcntl(int fd, int cmd, ...);
    int close(int fd);
    ssize_t read(int fd, void *buf, size_t count);
    ssize_t write(int fd, const void *buf, size_t count);
  ]])
  local O_NONBLOCK = 2048
  local F_SETFL = 4
  local pipefd = ffi.new("int[2]")
  local rc = ffi.C.pipe2(pipefd, 0)
  assert((rc == 0), "pipe2 failed: " .. tostring(rc))
  local rfd = pipefd[0]
  local wfd = pipefd[1]
  ffi.C.fcntl(rfd, F_SETFL, O_NONBLOCK)
  package.loaded["ipc"] = nil
  local m2 = dofile("lua/ipc.lua")
  local ip_raw2 = "\xC0\xA8\x02\x01"
  local mac_raw2 = "\xDE\xAD\xBE\xEF\x00\x01"
  local txid2, port2 = 0xBEEF, 12345
  local ok = m2.write_msg(wfd, txid2, ip_raw2, port2, mac_raw2)
  assert(ok, "write_msg failed")
  ffi.C.close(wfd)
  m2.drain_pipe(rfd, os.time)
  ffi.C.close(rfd)
  return assert((m2.is_pending(txid2, "192.168.2.1", port2, os.time)), "message absent de pending après drain_pipe")
end)
test("ipc — token expiré est rejeté (purge paresseuse)", function()
  package.loaded["ipc"] = nil
  local m3 = dofile("lua/ipc.lua")
  local pipefd3 = ffi.new("int[2]")
  assert((ffi.C.pipe2(pipefd3, 0) == 0), "pipe2 failed")
  local rfd3 = pipefd3[0]
  local wfd3 = pipefd3[1]
  ffi.C.fcntl(rfd3, 4, 2048)
  local ip_raw3 = "\x0A\x00\x00\x01"
  local txid3, port3 = 0x1111, 9999
  m3.write_msg(wfd3, txid3, ip_raw3, port3)
  ffi.C.close(wfd3)
  m3.drain_pipe(rfd3, function()
    return 0
  end)
  ffi.C.close(rfd3)
  assert((m3.is_pending(txid3, "10.0.0.1", port3, function()
    return 4
  end)), "token devrait être valide à t=4")
  return assert((not m3.is_pending(txid3, "10.0.0.1", port3, function()
    return 6
  end)), "token expiré doit être rejeté à t=6")
end)
io.write("\n── worker_q0 ──\n")
test("worker_q0 — paquet 2 questions (1 allowée + 1 bloquée) → NF_DROP, write_msg non appelé", function()
  package.loaded["parse/dns"] = nil
  local dns_mod = dofile("lua/parse/dns.lua")
  local txid = 0xCAFE
  local hdr = string.char(bit.rshift(bit.band(txid, 0xFF00), 8), bit.band(txid, 0xFF), 0x01, 0x00, 0, 2, 0, 0, 0, 0, 0, 0)
  local q1 = "\x06github\x03com\x00" .. string.char(0, 1, 0, 1)
  local q2 = "\x04evil\x03com\x00" .. string.char(0, 1, 0, 1)
  local dns_payload = hdr .. q1 .. q2
  local dns = dns_mod.parse_dns(dns_payload)
  assert(dns, "parse_dns a échoué")
  assert((#dns.questions == 2), string.format("attendu 2 questions, obtenu %d", #dns.questions))
  assert_eq(dns.questions[1].qname, "github.com", "Q1 qname")
  assert_eq(dns.questions[2].qname, "evil.com", "Q2 qname")
  local is_allowed_local
  is_allowed_local = function(qname)
    local local_allowed = {
      ["github.com"] = true
    }
    local name = qname:lower()
    if local_allowed[name] then
      return true
    end
    local pos = name:find(".", 1, true)
    while pos do
      if local_allowed[name:sub(pos + 1)] then
        return true
      end
      pos = name:find(".", pos + 1, true)
    end
    return false
  end
  local NF_ACCEPT, NF_DROP = 1, 0
  local verdict = NF_ACCEPT
  for _, q in ipairs(dns.questions) do
    if not is_allowed_local(q.qname) then
      verdict = NF_DROP
    end
  end
  local write_msg_would_be_called = (verdict == NF_ACCEPT)
  assert_eq(verdict, NF_DROP, "verdict doit être NF_DROP (evil.com est bloqué)")
  return assert_eq(write_msg_would_be_called, false, "write_msg ne doit pas être appelé quand verdict == NF_DROP")
end)
do
  local make_verdict
  make_verdict = function(allowed_set, questions)
    local NF_ACCEPT_V, NF_DROP_V = 1, 0
    local v = NF_ACCEPT_V
    for _, q in ipairs(questions) do
      local name = q.qname:lower()
      local matched = allowed_set[name]
      if not matched then
        local pos = name:find(".", 1, true)
        while pos and not matched do
          matched = allowed_set[name:sub(pos + 1)]
          pos = name:find(".", pos + 1, true)
        end
      end
      if not (matched) then
        v = NF_DROP_V
      end
    end
    return v
  end
  test("worker_q0 — question unique autorisée → NF_ACCEPT", function()
    package.loaded["parse/dns"] = nil
    local dns2 = dofile("lua/parse/dns.lua")
    local txid2 = 0x0001
    local hdr2 = string.char(bit.rshift(bit.band(txid2, 0xFF00), 8), bit.band(txid2, 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
    local q_ok = "\x06github\x03com\x00" .. string.char(0, 1, 0, 1)
    local parsed2 = dns2.parse_dns(hdr2 .. q_ok)
    assert(parsed2, "parse_dns nil")
    local verdict2 = make_verdict({
      ["github.com"] = true
    }, parsed2.questions)
    return assert_eq(verdict2, 1, "NF_ACCEPT pour github.com autorisé")
  end)
  test("worker_q0 — question unique bloquée → NF_DROP", function()
    package.loaded["parse/dns"] = nil
    local dns3 = dofile("lua/parse/dns.lua")
    local txid3 = 0x0002
    local hdr3 = string.char(bit.rshift(bit.band(txid3, 0xFF00), 8), bit.band(txid3, 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
    local q_bad = "\x04evil\x03com\x00" .. string.char(0, 1, 0, 1)
    local parsed3 = dns3.parse_dns(hdr3 .. q_bad)
    assert(parsed3, "parse_dns nil")
    local verdict3 = make_verdict({ }, parsed3.questions)
    return assert_eq(verdict3, 0, "NF_DROP pour evil.com bloqué")
  end)
  test("worker_q0 — sous-domaine autorisé via domaine parent", function()
    package.loaded["parse/dns"] = nil
    local dns4 = dofile("lua/parse/dns.lua")
    local txid4 = 0x0003
    local hdr4 = string.char(bit.rshift(bit.band(txid4, 0xFF00), 8), bit.band(txid4, 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
    local q_sub = "\x03api\x06github\x03com\x00" .. string.char(0, 1, 0, 1)
    local parsed4 = dns4.parse_dns(hdr4 .. q_sub)
    assert(parsed4, "parse_dns nil")
    local verdict4 = make_verdict({
      ["github.com"] = true
    }, parsed4.questions)
    return assert_eq(verdict4, 1, "NF_ACCEPT pour api.github.com (parent github.com autorisé)")
  end)
end
io.write("\n── parse/dns nouvelles fonctions ──\n")
local skip_name_bytes = m_dns.skip_name_bytes
local skip_rr = m_dns.skip_rr
local build_opt_rdata = m_dns.build_opt_rdata
local append_ede_to_dns = m_dns.append_ede_to_dns
test("skip_name_bytes — labels simples", function()
  local buf = "\x03www\x06github\x03com\x00"
  return assert_eq(skip_name_bytes(buf, 1), #buf, "consomme tout le buffer")
end)
test("skip_name_bytes — pointeur de compression (0xC00C)", function()
  local buf = "\xC0\x0C"
  return assert_eq(skip_name_bytes(buf, 1), 2, "pointeur = 2 octets consommés")
end)
test("skip_name_bytes — type réservé (0x40) → 0", function()
  local buf = "\x40foo"
  return assert_eq(skip_name_bytes(buf, 1), 0, "type réservé → 0")
end)
test("skip_name_bytes — label tronqué (longueur dépasse buffer) → 0", function()
  local buf = "\x0Aab"
  return assert_eq(skip_name_bytes(buf, 1), 0, "label tronqué → 0")
end)
test("skip_name_bytes — pointeur tronqué (octet 2 manquant) → 0", function()
  local buf = "\xC0"
  return assert_eq(skip_name_bytes(buf, 1), 0, "pointeur tronqué → 0")
end)
test("skip_rr — RR complet (root + TYPE A + CLASS IN + TTL=300 + rdlen=4)", function()
  local rr = "\x00" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(1, 2, 3, 4)
  return assert_eq(skip_rr(rr, 1), 15, "1 (name) + 10 (fixe) + 4 (rdata) = 15")
end)
test("skip_rr — buffer tronqué → nil", function()
  local buf = "\x00\x00\x01"
  return assert_eq(skip_rr(buf, 1), nil, "buffer tronqué → nil")
end)
test("build_opt_rdata — option simple code=0x0F data='AB'", function()
  local result = build_opt_rdata({
    {
      code = 0x0F,
      data = "AB"
    }
  })
  return assert_eq(result, "\x00\x0F\x00\x02AB", "OPTION-CODE(2) + OPTION-LEN(2) + DATA")
end)
test("build_opt_rdata — code=0 est ignoré (TBD IANA)", function()
  local result = build_opt_rdata({
    {
      code = 0,
      data = "test"
    }
  })
  return assert_eq(result, "", "code=0 → ignoré")
end)
test("build_opt_rdata — code=0 filtré parmi plusieurs options", function()
  local result = build_opt_rdata({
    {
      code = 1,
      data = "X"
    },
    {
      code = 0,
      data = "ignored"
    },
    {
      code = 2,
      data = "Y"
    }
  })
  local expected = "\x00\x01\x00\x01X" .. "\x00\x02\x00\x01Y"
  return assert_eq(result, expected, "seuls code=1 et code=2 encodés")
end)
local build_dns_with_opt
build_dns_with_opt = function(txid, qname_enc, opt_rdata)
  local rdlen = #opt_rdata
  local txid_hi = bit.rshift(bit.band(txid, 0xFF00), 8)
  local txid_lo = bit.band(txid, 0xFF)
  local rdlen_hi = bit.rshift(bit.band(rdlen, 0xFF00), 8)
  local rdlen_lo = bit.band(rdlen, 0xFF)
  local hdr = string.char(txid_hi, txid_lo, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 1)
  local q = qname_enc .. string.char(0, 1, 0, 1)
  local opt = "\x00" .. string.char(0x00, 0x29) .. string.char(0x04, 0x00) .. string.char(0, 0, 0, 0) .. string.char(rdlen_hi, rdlen_lo) .. opt_rdata
  return hdr .. q .. opt
end
test("append_ede_to_dns — OPT RR présent, RDLENGTH et longueur mis à jour", function()
  local qname = "\x03foo\x03com\x00"
  local dns = build_dns_with_opt(0x1234, qname, "")
  local new_dns = append_ede_to_dns(dns, {
    {
      code = 0x0F,
      data = "AB"
    }
  })
  assert(new_dns, "append_ede_to_dns retourne nil")
  local opt_start = 26
  assert_eq(new_dns:byte(opt_start + 9), 0, "RDLEN hi = 0")
  assert_eq(new_dns:byte(opt_start + 10), 6, "RDLEN lo = 6")
  return assert_eq(#new_dns, #dns + 6, "longueur augmentée de 6 octets")
end)
test("append_ede_to_dns — OPT avec RDATA existant préservé, option ajoutée", function()
  local qname = "\x03bar\x03com\x00"
  local existing = "\x00\x08\x00\x00"
  local dns = build_dns_with_opt(0x5678, qname, existing)
  local new_dns = append_ede_to_dns(dns, {
    {
      code = 0x0F,
      data = "AB"
    }
  })
  assert(new_dns, "append_ede_to_dns retourne nil")
  local opt_start = 26
  assert_eq(new_dns:byte(opt_start + 9), 0, "RDLEN hi = 0")
  assert_eq(new_dns:byte(opt_start + 10), 10, "RDLEN lo = 10")
  assert_eq(new_dns:byte(opt_start + 11), 0x00, "RDATA existant: code hi")
  assert_eq(new_dns:byte(opt_start + 12), 0x08, "RDATA existant: code lo = 8")
  assert_eq(new_dns:byte(opt_start + 13), 0x00, "RDATA existant: len hi")
  assert_eq(new_dns:byte(opt_start + 14), 0x00, "RDATA existant: len lo")
  assert_eq(new_dns:byte(opt_start + 15), 0x00, "EDE opt-code hi")
  assert_eq(new_dns:byte(opt_start + 16), 0x0F, "EDE opt-code lo = 15")
  assert_eq(new_dns:byte(opt_start + 17), 0x00, "EDE opt-len hi")
  return assert_eq(new_dns:byte(opt_start + 18), 0x02, "EDE opt-len lo = 2")
end)
test("append_ede_to_dns — sans OPT RR (arcount=0) → nil", function()
  local dns = make_dns("\x03foo\x03com\x00", 1, false, 0x5678)
  local result = append_ede_to_dns(dns, {
    {
      code = 0x0F,
      data = "x"
    }
  })
  return assert_eq(result, nil, "sans OPT RR → nil")
end)
test("append_ede_to_dns — payload tronqué (< 12 octets) → nil", function()
  local result = append_ede_to_dns("\x12\x34\x81\x80", {
    {
      code = 0x0F,
      data = "x"
    }
  })
  return assert_eq(result, nil, "payload < 12B → nil")
end)
test("append_ede_to_dns — toutes options code=0 → payload inchangé", function()
  local qname = "\x03baz\x03com\x00"
  local dns = build_dns_with_opt(0x9999, qname, "")
  local result = append_ede_to_dns(dns, {
    {
      code = 0,
      data = "ignored"
    }
  })
  return assert_eq(result, dns, "build_opt_rdata vide → retourne payload inchangé")
end)
io.write("\n── parse/ndpi helpers ──\n")
package.loaded["ffi_ndpi"] = {
  ffi = ffi,
  ndpi_lib = { },
  major = 4
}
package.loaded["parse.ndpi_v4"] = {
  init = function()
    return nil
  end,
  detect = function()
    return 0, 0
  end,
  cleanup = function()
    return nil
  end
}
package.loaded["parse.ndpi_v5"] = {
  init = function()
    return nil
  end,
  detect = function()
    return 0, 0
  end,
  cleanup = function()
    return nil
  end
}
local m_ndpi2 = dofile("lua/parse/ndpi.lua")
local extract_dns_payload = m_ndpi2.extract_dns_payload
local patch_ttl_in_dns = m_ndpi2.patch_ttl_in_dns
local replace_dns_payload = m_ndpi2.replace_dns_payload
test("extract_dns_payload — UDP : retourne la sous-chaîne DNS", function()
  local dns = make_dns("\x06github\x03com\x00", 1, false, 0xABCD)
  local raw = make_ipv4_udp_dns("192.168.1.2", "8.8.8.8", 54321, 53, dns)
  local pkt = {
    ip = {
      version = 4,
      ihl = 20
    },
    l4 = {
      proto = "udp",
      off = 28,
      payload_len = #dns
    }
  }
  return assert_eq(extract_dns_payload(raw, pkt), dns, "payload DNS extrait correctement")
end)
test("extract_dns_payload — TCP : retourne pkt.tcp_dns_raw", function()
  local dns = make_dns("\x03foo\x03com\x00", 1, false, 0x4321)
  local pkt = {
    l4 = {
      proto = "tcp"
    },
    tcp_dns_raw = dns
  }
  return assert_eq(extract_dns_payload("ignored", pkt), dns, "retourne pkt.tcp_dns_raw")
end)
test("patch_ttl_in_dns — réécrit TTL à l'offset 0-based correct, class intact", function()
  local qname_enc = "\x06github\x03com\x00"
  local hdr = string.char(0x56, 0x78, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  local question = qname_enc .. string.char(0, 1, 0, 1)
  local rr = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(1, 2, 3, 4)
  local dns_str = hdr .. question .. rr
  local ttl_off = 34
  local result = patch_ttl_in_dns(dns_str, {
    {
      ttl_offset = ttl_off
    }
  }, 60)
  assert(result, "patch_ttl_in_dns ne retourne pas nil")
  assert_eq(#result, #dns_str, "longueur inchangée")
  assert_eq(result:byte(33), 0x00, "CLASS hi non corrompu")
  assert_eq(result:byte(34), 0x01, "CLASS lo = IN (1) non corrompu")
  assert_eq(result:byte(35), 0x00, "TTL byte 0 = 0x00")
  assert_eq(result:byte(36), 0x00, "TTL byte 1 = 0x00")
  assert_eq(result:byte(37), 0x00, "TTL byte 2 = 0x00")
  return assert_eq(result:byte(38), 60, "TTL byte 3 = 60")
end)
test("patch_ttl_in_dns — answers vide → payload inchangé", function()
  local dns_str = make_dns("\x03foo\x03com\x00", 1, false, 0x1111)
  local result = patch_ttl_in_dns(dns_str, { }, 60)
  assert(result, "retourne non-nil même sans answers")
  return assert_eq(result, dns_str, "payload inchangé si answers vide")
end)
test("replace_dns_payload — IPv4 UDP : longueurs IP et UDP mises à jour", function()
  local dns_orig = make_dns("\x06github\x03com\x00", 1, false, 0xABCD)
  local raw = make_ipv4_udp_dns("8.8.8.8", "192.168.1.42", 53, 54321, dns_orig)
  local pkt = {
    ip = {
      version = 4,
      ihl = 20
    },
    l4 = {
      proto = "udp",
      off = 28,
      payload_len = #dns_orig
    }
  }
  local new_dns = dns_orig .. "\x00\x00\x00\x00"
  local result = replace_dns_payload(raw, pkt, new_dns)
  assert(result, "replace_dns_payload nil")
  local expected_total = 20 + 8 + #new_dns
  assert_eq(#result, expected_total, "longueur totale du paquet")
  local ip_len = bit.bor(bit.lshift(result:byte(3), 8), result:byte(4))
  assert_eq(ip_len, expected_total, "IP total_len mis à jour")
  local udp_len_field = bit.bor(bit.lshift(result:byte(25), 8), result:byte(26))
  assert_eq(udp_len_field, 8 + #new_dns, "UDP length mis à jour")
  return assert_eq(result:sub(29, 28 + #new_dns), new_dns, "payload DNS correct")
end)
test("replace_dns_payload — IPv4 TCP : longueur IP et DNS prefix mis à jour", function()
  local dns_orig = make_dns("\x03foo\x03com\x00", 1, false, 0x2222)
  local raw = make_ipv4_tcp_dns("8.8.8.8", "192.168.1.42", 53, 54321, dns_orig)
  local pkt = {
    ip = {
      version = 4,
      ihl = 20
    },
    l4 = {
      proto = "tcp"
    },
    tcp_init_seq = 0
  }
  local new_dns = dns_orig .. "\xAB\xCD"
  local result = replace_dns_payload(raw, pkt, new_dns)
  assert(result, "replace_dns_payload TCP nil")
  local expected_total = 20 + 20 + 2 + #new_dns
  assert_eq(#result, expected_total, "longueur totale TCP")
  local ip_len = bit.bor(bit.lshift(result:byte(3), 8), result:byte(4))
  assert_eq(ip_len, expected_total, "IP total_len mis à jour")
  local dns_prefix = bit.bor(bit.lshift(result:byte(41), 8), result:byte(42))
  assert_eq(dns_prefix, #new_dns, "DNS length prefix (TCP) = longueur DNS")
  return assert_eq(result:sub(43, 42 + #new_dns), new_dns, "payload DNS TCP correct")
end)
io.write("\n── ipc refused ──\n")
test("encode_msg refused=true IPv4 → MSG_IPV4_REFUSED (0x52)", function()
  local ip_raw = "\xC0\xA8\x01\x2A"
  local msg = m_ipc.encode_msg(0x1234, ip_raw, 54321, nil, true)
  assert_eq(#msg, 27, "taille = 27")
  local decoded = m_ipc.decode_msg(msg)
  assert(decoded, "decode_msg nil")
  assert_eq(decoded.msg_type, m_ipc.MSG_IPV4_REFUSED, "msg_type = MSG_IPV4_REFUSED")
  assert_eq(decoded.refused, true, "refused = true")
  return assert_eq(decoded.ipv4, true, "ipv4 = true")
end)
test("decode_msg MSG_IPV6_REFUSED (0x72) → refused=true, ipv4=false", function()
  local ip6_raw = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  local msg = m_ipc.encode_msg(0xABCD, ip6_raw, 5353, nil, true)
  local decoded = m_ipc.decode_msg(msg)
  assert(decoded, "decode_msg nil")
  assert_eq(decoded.refused, true, "refused = true")
  assert_eq(decoded.ipv4, false, "ipv4 = false")
  return assert_eq(decoded.msg_type, 0x72, "msg_type = 0x72")
end)
test("write_refused_msg + drain_pipe + get_pending_entry → entry.refused = true", function()
  package.loaded["ipc"] = nil
  local m_rip = dofile("lua/ipc.lua")
  local pfd = ffi.new("int[2]")
  assert((ffi.C.pipe2(pfd, 0) == 0), "pipe2")
  local rfd5, wfd5 = pfd[0], pfd[1]
  ffi.C.fcntl(rfd5, 4, 2048)
  local ip5 = "\x05\x05\x05\x05"
  local ok = m_rip.write_refused_msg(wfd5, 0x9999, ip5, 5555)
  assert(ok, "write_refused_msg failed")
  ffi.C.close(wfd5)
  m_rip.drain_pipe(rfd5, function()
    return 0
  end)
  ffi.C.close(rfd5)
  local entry = m_rip.get_pending_entry(0x9999, "5.5.5.5", 5555, function()
    return 0
  end)
  assert(entry, "get_pending_entry retourne nil")
  assert_eq(entry.refused, true, "entry.refused = true")
  return assert((entry.expire > 0), "entry.expire > 0")
end)
io.write("\n── filter ──\n")
local bsearch
bsearch = require("filter.lib.bsearch").bsearch
test("bsearch — trouvé en début", function()
  local arr = ffi.new("uint64_t[3]", {
    100ULL,
    200ULL,
    300ULL
  })
  return assert_eq((bsearch(arr, 3, 100ULL)), true, "bsearch(100)")
end)
test("bsearch — trouvé en milieu", function()
  local arr = ffi.new("uint64_t[3]", {
    100ULL,
    200ULL,
    300ULL
  })
  return assert_eq((bsearch(arr, 3, 200ULL)), true, "bsearch(200)")
end)
test("bsearch — trouvé en fin", function()
  local arr = ffi.new("uint64_t[3]", {
    100ULL,
    200ULL,
    300ULL
  })
  return assert_eq((bsearch(arr, 3, 300ULL)), true, "bsearch(300)")
end)
test("bsearch — absent", function()
  local arr = ffi.new("uint64_t[3]", {
    100ULL,
    200ULL,
    300ULL
  })
  return assert_eq((bsearch(arr, 3, 150ULL)), false, "bsearch(150)")
end)
test("bsearch — tableau vide", function()
  local arr = ffi.new("uint64_t[0]")
  return assert_eq((bsearch(arr, 0, 42ULL)), false, "bsearch vide")
end)
local ipcalc = require("filter.lib.ipcalc")
test("ipcalc — IPv4 dans sous-réseau", function()
  local n = ipcalc.Net("192.168.1.0/24")
  assert(n, "Net() non nil")
  return assert_eq((n:contains("192.168.1.42")), true, "192.168.1.42 dans /24")
end)
test("ipcalc — IPv4 hors sous-réseau", function()
  local n = ipcalc.Net("192.168.1.0/24")
  return assert_eq((n:contains("10.0.0.1")), false, "10.0.0.1 hors /24")
end)
test("ipcalc — masque /16", function()
  local n = ipcalc.Net("10.0.0.0/8")
  assert_eq((n:contains("10.255.255.1")), true, "10.x dans /8")
  return assert_eq((n:contains("11.0.0.1")), false, "11.x hors /8")
end)
test("ipcalc — IPv6 dans sous-réseau", function()
  local n = ipcalc.Net("2001:db8::/32")
  return assert_eq((n:contains("2001:db8::1")), true, "2001:db8::1 dans /32")
end)
test("ipcalc — IPv6 hors sous-réseau", function()
  local n = ipcalc.Net("2001:db8::/32")
  return assert_eq((n:contains("2001:db9::1")), false, "2001:db9::1 hors /32")
end)
test("ipcalc — CIDR invalide → nil", function()
  local n = ipcalc.Net("not_an_ip/24")
  return assert((n == nil), "Net invalide → nil")
end)
local to_domain = require("filter.conditions.to_domain")
test("to_domain — correspondance exacte", function()
  local f = (to_domain({ }))("github.com")
  local v, r = f({
    domain = "github.com"
  })
  return assert_eq(v, true, "exact match")
end)
test("to_domain — sous-domaine autorisé", function()
  local f = (to_domain({ }))("github.com")
  local v = f({
    domain = "api.github.com"
  })
  return assert_eq(v, true, "sous-domaine")
end)
test("to_domain — domaine différent bloqué", function()
  local f = (to_domain({ }))("github.com")
  local v = f({
    domain = "notgithub.com"
  })
  return assert_eq(v, false, "pas de correspondance")
end)
test("to_domain — domaine vide → faux", function()
  local f = (to_domain({ }))("github.com")
  local v = f({
    domain = nil
  })
  return assert_eq(v, false, "domaine nil")
end)
local to_domains = require("filter.conditions.to_domains")
test("to_domains — OR logique", function()
  local f = (to_domains({ }))({
    "github.com",
    "debian.org"
  })
  assert_eq((f({
    domain = "github.com"
  })), true, "github OK")
  assert_eq((f({
    domain = "packages.debian.org"
  })), true, "debian OK")
  return assert_eq((f({
    domain = "evil.com"
  })), false, "evil non")
end)
test("to_domains — liste vide → faux", function()
  local f = (to_domains({ }))({ })
  return assert_eq((f({
    domain = "github.com"
  })), false, "liste vide → false")
end)
test("to_domains — un seul domaine, match exact", function()
  local f = (to_domains({ }))({
    "example.com"
  })
  return assert_eq((f({
    domain = "example.com"
  })), true, "exact match")
end)
test("to_domains — un seul domaine, sous-domaine", function()
  local f = (to_domains({ }))({
    "example.com"
  })
  return assert_eq((f({
    domain = "www.example.com"
  })), true, "sous-domaine match")
end)
test("to_domains — un seul domaine, domaine différent", function()
  local f = (to_domains({ }))({
    "example.com"
  })
  return assert_eq((f({
    domain = "other.com"
  })), false, "pas de match")
end)
local to_domainlists = require("filter.conditions.to_domainlists")
test("to_domainlists — OR sur plusieurs listes", function()
  do
    local xxhash2 = require("ffi_xxhash")
    local TMPBIN2 = "./tmp/test_filter_domainlist2.bin"
    local test_domains2 = {
      "malware.bad",
      "tracker.bad"
    }
    local hashes2
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #test_domains2 do
        local d = test_domains2[_index_0]
        _accum_0[_len_0] = xxhash2.xxh64(d)
        _len_0 = _len_0 + 1
      end
      hashes2 = _accum_0
    end
    table.sort(hashes2, function(a, b)
      return a < b
    end)
    local arr2 = ffi.new("uint64_t[?]", #hashes2)
    for i, h in ipairs(hashes2) do
      arr2[i - 1] = h
    end
    local fd2 = io.open(TMPBIN2, "wb")
    fd2:write(ffi.string(arr2, #hashes2 * 8))
    fd2:close()
    local xxhash3 = require("ffi_xxhash")
    local TMPBIN3 = "./tmp/test_filter_domainlist3.bin"
    local test_domains3 = {
      "github.com",
      "debian.org"
    }
    local hashes3
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #test_domains3 do
        local d = test_domains3[_index_0]
        _accum_0[_len_0] = xxhash3.xxh64(d)
        _len_0 = _len_0 + 1
      end
      hashes3 = _accum_0
    end
    table.sort(hashes3, function(a, b)
      return a < b
    end)
    local arr3 = ffi.new("uint64_t[?]", #hashes3)
    for i, h in ipairs(hashes3) do
      arr3[i - 1] = h
    end
    local fd3 = io.open(TMPBIN3, "wb")
    fd3:write(ffi.string(arr3, #hashes3 * 8))
    fd3:close()
    local cfg_dl = {
      domainlists_dir = "./tmp"
    }
    test("to_domainlists — domaine dans première liste", function()
      local f = (to_domainlists(cfg_dl))({
        "test_filter_domainlist3",
        "test_filter_domainlist2"
      })
      return assert_eq((f({
        domain = "github.com"
      })), true, "github.com dans liste 1")
    end)
    test("to_domainlists — domaine dans deuxième liste", function()
      local f = (to_domainlists(cfg_dl))({
        "test_filter_domainlist3",
        "test_filter_domainlist2"
      })
      return assert_eq((f({
        domain = "malware.bad"
      })), true, "malware.bad dans liste 2")
    end)
    test("to_domainlists — domaine absent de toutes les listes", function()
      local f = (to_domainlists(cfg_dl))({
        "test_filter_domainlist3",
        "test_filter_domainlist2"
      })
      return assert_eq((f({
        domain = "safe.com"
      })), false, "safe.com absent")
    end)
    test("to_domainlists — liste vide → faux", function()
      local f = (to_domainlists(cfg_dl))({ })
      return assert_eq((f({
        domain = "github.com"
      })), false, "liste vide → false")
    end)
    os.remove(TMPBIN2)
    return os.remove(TMPBIN3)
  end
end)
local to_domainlist = require("filter.conditions.to_domainlist")
local TMPDIR = "./tmp"
local TMPBIN = TMPDIR .. "/test_filter_domainlist.bin"
do
  local xxhash = require("ffi_xxhash")
  local test_domains = {
    "github.com",
    "debian.org",
    "cloudflare.com"
  }
  local hashes
  do
    local _accum_0 = { }
    local _len_0 = 1
    for _index_0 = 1, #test_domains do
      local d = test_domains[_index_0]
      _accum_0[_len_0] = xxhash.xxh64(d)
      _len_0 = _len_0 + 1
    end
    hashes = _accum_0
  end
  table.sort(hashes, function(a, b)
    return a < b
  end)
  local arr = ffi.new("uint64_t[?]", #hashes)
  for i, h in ipairs(hashes) do
    arr[i - 1] = h
  end
  local fd = io.open(TMPBIN, "wb")
  fd:write(ffi.string(arr, #hashes * 8))
  fd:close()
end
test("to_domainlist — domaine présent (fichier .bin)", function()
  local cfg = {
    domainlists_dir = TMPDIR
  }
  local f = (to_domainlist(cfg))("test_filter_domainlist")
  return assert_eq((f({
    domain = "github.com"
  })), true, "github.com dans liste")
end)
test("to_domainlist — sous-domaine présent", function()
  local cfg = {
    domainlists_dir = TMPDIR
  }
  local f = (to_domainlist(cfg))("test_filter_domainlist")
  return assert_eq((f({
    domain = "api.github.com"
  })), true, "api.github.com sous-domaine")
end)
test("to_domainlist — domaine absent", function()
  local cfg = {
    domainlists_dir = TMPDIR
  }
  local f = (to_domainlist(cfg))("test_filter_domainlist")
  return assert_eq((f({
    domain = "evil.com"
  })), false, "evil.com absent")
end)
test("to_domainlist — domainlists_dir absent → faux", function()
  local cfg = { }
  local f = (to_domainlist(cfg))("nonexistent")
  return assert_eq((f({
    domain = "github.com"
  })), false, "domainlists_dir manquant → false")
end)
test("to_domainlist — nom absolu → faux", function()
  local cfg = {
    domainlists_dir = TMPDIR
  }
  local f = (to_domainlist(cfg))("/etc/passwd")
  return assert_eq((f({
    domain = "github.com"
  })), false, "chemin absolu rejeté")
end)
test("to_domainlist — traversée répertoire → faux", function()
  local cfg = {
    domainlists_dir = TMPDIR
  }
  local f = (to_domainlist(cfg))("../secret")
  return assert_eq((f({
    domain = "github.com"
  })), false, ".. rejeté")
end)
test("to_domainlist — suffixe .bin → faux", function()
  local cfg = {
    domainlists_dir = TMPDIR
  }
  local f = (to_domainlist(cfg))("test_filter_domainlist.bin")
  return assert_eq((f({
    domain = "github.com"
  })), false, ".bin en suffixe rejeté")
end)
local from_mac = require("filter.conditions.from_mac")
test("from_mac — MAC correspondant", function()
  local f = (from_mac({ }))("aa:bb:cc:dd:ee:ff")
  return assert_eq((f({
    mac = "aa:bb:cc:dd:ee:ff"
  })), true, "MAC match")
end)
test("from_mac — MAC différent", function()
  local f = (from_mac({ }))("aa:bb:cc:dd:ee:ff")
  return assert_eq((f({
    mac = "00:00:00:00:00:00"
  })), false, "MAC no match")
end)
test("from_mac — MAC absent dans req", function()
  local f = (from_mac({ }))("aa:bb:cc:dd:ee:ff")
  return assert_eq((f({
    mac = nil
  })), false, "MAC nil")
end)
local from_net = require("filter.conditions.from_net")
test("from_net — IP dans réseau", function()
  local f = (from_net({ }))("192.168.0.0/16")
  return assert_eq((f({
    src_ip = "192.168.1.42"
  })), true, "IP dans LAN")
end)
test("from_net — IP hors réseau", function()
  local f = (from_net({ }))("192.168.0.0/16")
  return assert_eq((f({
    src_ip = "10.0.0.1"
  })), false, "IP hors LAN")
end)
test("from_net — IP absente dans req", function()
  local f = (from_net({ }))("192.168.0.0/16")
  local v = f({
    src_ip = nil
  })
  return assert_eq(v, false, "src_ip nil")
end)
local from_netlist = require("filter.conditions.from_netlist")
local from_netlists = require("filter.conditions.from_netlists")
do
  local NETLIST_CFG = {
    nets = {
      lan = {
        "192.168.0.0/16",
        "10.0.0.0/8"
      },
      dmz = {
        "172.16.0.0/12"
      }
    }
  }
  test("from_netlist — IP dans la netlist (premier CIDR)", function()
    local f = (from_netlist(NETLIST_CFG))("lan")
    return assert_eq((f({
      src_ip = "192.168.1.42"
    })), true, "192.168.1.42 dans lan")
  end)
  test("from_netlist — IP dans la netlist (deuxième CIDR)", function()
    local f = (from_netlist(NETLIST_CFG))("lan")
    return assert_eq((f({
      src_ip = "10.5.0.1"
    })), true, "10.5.0.1 dans lan")
  end)
  test("from_netlist — IP hors de la netlist", function()
    local f = (from_netlist(NETLIST_CFG))("lan")
    return assert_eq((f({
      src_ip = "8.8.8.8"
    })), false, "8.8.8.8 hors lan")
  end)
  test("from_netlist — netlist inconnue → faux", function()
    local f = (from_netlist(NETLIST_CFG))("unknown")
    return assert_eq((f({
      src_ip = "192.168.1.1"
    })), false, "netlist inconnue → false")
  end)
  test("from_netlist — src_ip nil → faux", function()
    local f = (from_netlist(NETLIST_CFG))("lan")
    return assert_eq((f({
      src_ip = nil
    })), false, "src_ip nil → false")
  end)
  test("from_netlists — OR sur plusieurs netlists (première)", function()
    local f = (from_netlists(NETLIST_CFG))({
      "lan",
      "dmz"
    })
    return assert_eq((f({
      src_ip = "192.168.0.1"
    })), true, "dans lan")
  end)
  test("from_netlists — OR sur plusieurs netlists (deuxième)", function()
    local f = (from_netlists(NETLIST_CFG))({
      "lan",
      "dmz"
    })
    return assert_eq((f({
      src_ip = "172.16.1.1"
    })), true, "dans dmz")
  end)
  test("from_netlists — IP hors de toutes les netlists", function()
    local f = (from_netlists(NETLIST_CFG))({
      "lan",
      "dmz"
    })
    return assert_eq((f({
      src_ip = "1.2.3.4"
    })), false, "1.2.3.4 hors de tout")
  end)
  test("from_netlists — liste vide → faux", function()
    local f = (from_netlists(NETLIST_CFG))({ })
    return assert_eq((f({
      src_ip = "192.168.1.1"
    })), false, "liste vide → false")
  end)
end
local from_nets = require("filter.conditions.from_nets")
test("from_nets — IP dans l'un des CIDRs (premier)", function()
  local f = (from_nets({ }))({
    "192.168.0.0/16",
    "10.0.0.0/8"
  })
  return assert_eq((f({
    src_ip = "192.168.1.1"
  })), true, "192.168.1.1 dans premier CIDR")
end)
test("from_nets — IP dans l'un des CIDRs (deuxième)", function()
  local f = (from_nets({ }))({
    "192.168.0.0/16",
    "10.0.0.0/8"
  })
  return assert_eq((f({
    src_ip = "10.5.0.1"
  })), true, "10.5.0.1 dans deuxième CIDR")
end)
test("from_nets — IP hors de tous les CIDRs", function()
  local f = (from_nets({ }))({
    "192.168.0.0/16",
    "10.0.0.0/8"
  })
  return assert_eq((f({
    src_ip = "8.8.8.8"
  })), false, "8.8.8.8 hors de tout")
end)
test("from_nets — liste vide → faux", function()
  local f = (from_nets({ }))({ })
  return assert_eq((f({
    src_ip = "192.168.1.1"
  })), false, "liste vide → false")
end)
test("from_nets — src_ip nil → faux", function()
  local f = (from_nets({ }))({
    "192.168.0.0/16"
  })
  return assert_eq((f({
    src_ip = nil
  })), false, "src_ip nil → false")
end)
local from_macs = require("filter.conditions.from_macs")
test("from_macs — MAC dans la liste (première)", function()
  local f = (from_macs({ }))({
    "aa:bb:cc:dd:ee:ff",
    "11:22:33:44:55:66"
  })
  return assert_eq((f({
    mac = "aa:bb:cc:dd:ee:ff"
  })), true, "première MAC match")
end)
test("from_macs — MAC dans la liste (deuxième)", function()
  local f = (from_macs({ }))({
    "aa:bb:cc:dd:ee:ff",
    "11:22:33:44:55:66"
  })
  return assert_eq((f({
    mac = "11:22:33:44:55:66"
  })), true, "deuxième MAC match")
end)
test("from_macs — MAC hors de la liste", function()
  local f = (from_macs({ }))({
    "aa:bb:cc:dd:ee:ff",
    "11:22:33:44:55:66"
  })
  return assert_eq((f({
    mac = "de:ad:be:ef:00:01"
  })), false, "MAC absente")
end)
test("from_macs — liste vide → faux", function()
  local f = (from_macs({ }))({ })
  return assert_eq((f({
    mac = "aa:bb:cc:dd:ee:ff"
  })), false, "liste vide → false")
end)
test("from_macs — MAC nil → faux", function()
  local f = (from_macs({ }))({
    "aa:bb:cc:dd:ee:ff"
  })
  return assert_eq((f({
    mac = nil
  })), false, "mac nil → false")
end)
test("from_macs — insensible à la casse", function()
  local f = (from_macs({ }))({
    "AA:BB:CC:DD:EE:FF"
  })
  return assert_eq((f({
    mac = "aa:bb:cc:dd:ee:ff"
  })), true, "normalisation lowercase")
end)
local from_maclist = require("filter.conditions.from_maclist")
local from_maclists = require("filter.conditions.from_maclists")
do
  local MACLIST_CFG = {
    macs = {
      trusted = {
        "aa:bb:cc:dd:ee:ff",
        "11:22:33:44:55:66"
      },
      printers = {
        "de:ad:be:ef:00:01"
      }
    }
  }
  test("from_maclist — MAC dans le groupe", function()
    local f = (from_maclist(MACLIST_CFG))("trusted")
    return assert_eq((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })), true, "première MAC du groupe")
  end)
  test("from_maclist — deuxième MAC du groupe", function()
    local f = (from_maclist(MACLIST_CFG))("trusted")
    return assert_eq((f({
      mac = "11:22:33:44:55:66"
    })), true, "deuxième MAC du groupe")
  end)
  test("from_maclist — MAC hors du groupe", function()
    local f = (from_maclist(MACLIST_CFG))("trusted")
    return assert_eq((f({
      mac = "de:ad:be:ef:00:01"
    })), false, "MAC du groupe printers")
  end)
  test("from_maclist — groupe inconnu → faux", function()
    local f = (from_maclist(MACLIST_CFG))("unknown")
    return assert_eq((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })), false, "groupe inconnu → false")
  end)
  test("from_maclist — MAC nil → faux", function()
    local f = (from_maclist(MACLIST_CFG))("trusted")
    return assert_eq((f({
      mac = nil
    })), false, "mac nil → false")
  end)
  test("from_maclists — OR : premier groupe match", function()
    local f = (from_maclists(MACLIST_CFG))({
      "trusted",
      "printers"
    })
    return assert_eq((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })), true, "dans trusted")
  end)
  test("from_maclists — OR : deuxième groupe match", function()
    local f = (from_maclists(MACLIST_CFG))({
      "trusted",
      "printers"
    })
    return assert_eq((f({
      mac = "de:ad:be:ef:00:01"
    })), true, "dans printers")
  end)
  test("from_maclists — MAC hors de tous les groupes", function()
    local f = (from_maclists(MACLIST_CFG))({
      "trusted",
      "printers"
    })
    return assert_eq((f({
      mac = "00:00:00:00:00:00"
    })), false, "MAC absente partout")
  end)
  test("from_maclists — liste vide → faux", function()
    local f = (from_maclists(MACLIST_CFG))({ })
    return assert_eq((f({
      mac = "aa:bb:cc:dd:ee:ff"
    })), false, "liste vide → false")
  end)
end
local stolen_computer = require("filter.conditions.stolen_computer")
test("stolen_computer — MAC blacklisté", function()
  local f = (stolen_computer({ }))({
    "de:ad:be:ef:00:01"
  })
  return assert_eq((f({
    mac = "de:ad:be:ef:00:01"
  })), true, "volé")
end)
test("stolen_computer — MAC non blacklisté", function()
  local f = (stolen_computer({ }))({
    "de:ad:be:ef:00:01"
  })
  return assert_eq((f({
    mac = "aa:bb:cc:dd:ee:ff"
  })), false, "non volé")
end)
test("stolen_computer — liste vide → faux", function()
  local f = (stolen_computer({ }))({ })
  return assert_eq((f({
    mac = "de:ad:be:ef:00:01"
  })), false, "liste vide → false")
end)
test("stolen_computer — MAC nil → faux", function()
  local f = (stolen_computer({ }))({
    "de:ad:be:ef:00:01"
  })
  return assert_eq((f({
    mac = nil
  })), false, "mac nil → false")
end)
local in_time = require("filter.conditions.in_time")
test("in_time — dans la fenêtre", function()
  local cfg = {
    times = {
      allday = {
        "00:00",
        "23:59"
      }
    }
  }
  local f = (in_time(cfg))("allday")
  local v, r = f({
    ts = os.time()
  })
  return assert_eq(v, true, "dans allday")
end)
test("in_time — hors fenêtre", function()
  local cfg = {
    times = {
      never = {
        "25:00",
        "25:01"
      }
    }
  }
  local f = (in_time(cfg))("never")
  local v = f({
    ts = os.time()
  })
  return assert_eq(v, false, "hors fenêtre absurde")
end)
test("in_time — fenêtre inconnue → faux", function()
  local cfg = {
    times = { }
  }
  local f = (in_time(cfg))("doesnotexist")
  return assert_eq((f({
    ts = os.time()
  })), false, "fenêtre inconnue")
end)
local in_times = require("filter.conditions.in_times")
test("in_times — OR : première fenêtre match", function()
  local cfg = {
    times = {
      allday = {
        "00:00",
        "23:59"
      },
      never = {
        "25:00",
        "25:01"
      }
    }
  }
  local f = (in_times(cfg))({
    "allday",
    "never"
  })
  return assert_eq((f({
    ts = os.time()
  })), true, "allday OR never → true (allday match)")
end)
test("in_times — OR : deuxième fenêtre match (première ne match pas)", function()
  local cfg = {
    times = {
      never = {
        "25:00",
        "25:01"
      },
      allday = {
        "00:00",
        "23:59"
      }
    }
  }
  local f = (in_times(cfg))({
    "never",
    "allday"
  })
  return assert_eq((f({
    ts = os.time()
  })), true, "never OR allday → true (allday match)")
end)
test("in_times — OR : aucune fenêtre ne match", function()
  local cfg = {
    times = {
      never = {
        "25:00",
        "25:01"
      },
      also_never = {
        "26:00",
        "26:01"
      }
    }
  }
  local f = (in_times(cfg))({
    "never",
    "also_never"
  })
  return assert_eq((f({
    ts = os.time()
  })), false, "aucune fenêtre → false")
end)
test("in_times — liste vide → faux", function()
  local cfg = {
    times = {
      allday = {
        "00:00",
        "23:59"
      }
    }
  }
  local f = (in_times(cfg))({ })
  return assert_eq((f({
    ts = os.time()
  })), false, "liste vide → false")
end)
local m_rule = require("filter.rule")
local TEST_CFG = {
  times = {
    business = {
      "00:00",
      "23:59"
    }
  }
}
local TEST_RULES_CFG = {
  {
    description = "Infra locale toujours OK",
    conditions = {
      to_domains = {
        "local",
        "home.arpa"
      }
    },
    actions = {
      "allow"
    }
  },
  {
    description = "Machines volées bloquées",
    conditions = {
      stolen_computer = {
        "de:ad:be:ef:00:01"
      }
    },
    actions = {
      "deny"
    }
  },
  {
    description = "LAN autorisé",
    conditions = {
      from_net = "192.168.0.0/16",
      to_domain = "github.com"
    },
    actions = {
      "allow"
    }
  },
  {
    description = "Refus par défaut",
    conditions = { },
    actions = {
      "deny"
    }
  }
}
do
  local cfg = {
    rules = TEST_RULES_CFG,
    times = TEST_CFG.times
  }
  local rules = m_rule.compile_rules(cfg)
  test("rule.decide — domaine local → allow", function()
    local v, m = m_rule.decide(rules, {
      domain = "gateway.local",
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "192.168.1.1",
      ts = os.time()
    })
    return assert_eq(v, true, "local domain autorisé")
  end)
  test("rule.decide — machine volée → deny même sur domaine non-local", function()
    local v, m = m_rule.decide(rules, {
      domain = "github.com",
      mac = "de:ad:be:ef:00:01",
      src_ip = "192.168.1.2",
      ts = os.time()
    })
    return assert_eq(v, false, "volée + github.com → deny")
  end)
  test("rule.decide — LAN + domain → allow", function()
    local v, m = m_rule.decide(rules, {
      domain = "github.com",
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "192.168.1.3",
      ts = os.time()
    })
    return assert_eq(v, true, "LAN + github.com autorisé")
  end)
  test("rule.decide — hors LAN + domain → default deny", function()
    local v, m = m_rule.decide(rules, {
      domain = "github.com",
      mac = "aa:bb:cc:dd:ee:ff",
      src_ip = "1.2.3.4",
      ts = os.time()
    })
    return assert_eq(v, false, "WAN + github.com → deny")
  end)
  test("rule.decide — aucune règle ne correspond → false", function()
    local rules_empty = m_rule.compile_rules({
      rules = { }
    })
    local v, m = m_rule.decide(rules_empty, {
      domain = "github.com",
      ts = os.time()
    })
    return assert_eq(v, false, "aucune règle → deny par défaut")
  end)
end
os.remove(TMPBIN)
io.write("\n── parse_domains ──\n")
local parse, parse_simple, parse_hosts, parse_adblock, is_valid
do
  local _obj_0 = require("filter.lib.parse_domains")
  parse, parse_simple, parse_hosts, parse_adblock, is_valid = _obj_0.parse, _obj_0.parse_simple, _obj_0.parse_hosts, _obj_0.parse_adblock, _obj_0.is_valid
end
test("parse_domains.is_valid — domaine valide", function()
  return assert_eq((is_valid("example.com")), true, "example.com")
end)
test("parse_domains.is_valid — domaine avec sous-domaine", function()
  return assert_eq((is_valid("ads.example.com")), true, "ads.example.com")
end)
test("parse_domains.is_valid — chaîne vide → invalide", function()
  return assert_eq((is_valid("")), false, "vide")
end)
test("parse_domains.is_valid — IPv4 → invalide", function()
  return assert_eq((is_valid("1.2.3.4")), false, "IPv4")
end)
test("parse_domains.is_valid — IPv6 → invalide", function()
  return assert_eq((is_valid("::1")), false, "IPv6")
end)
test("parse_domains.is_valid — sans point → invalide", function()
  return assert_eq((is_valid("localhost")), false, "pas de point")
end)
test("parse_domains.is_valid — trop long → invalide", function()
  return assert_eq((is_valid((string.rep("a", 254)))), false, "trop long")
end)
test("parse_domains.is_valid — caractères invalides → invalide", function()
  return assert_eq((is_valid("bad domain.com")), false, "espace")
end)
do
  local text = [[# Commentaire
example.com
  ads.example.com
DOUBLECLICK.NET
# autre commentaire
invalide
]]
  local result = parse_simple(text)
  test("parse_simple — nombre de domaines extraits", function()
    return assert_eq(#result, 3, "3 domaines")
  end)
  test("parse_simple — normalisation minuscules", function()
    local found = false
    for _index_0 = 1, #result do
      local d = result[_index_0]
      if d == "doubleclick.net" then
        found = true
      end
    end
    return assert(found, "doubleclick.net normalisé")
  end)
  test("parse_simple — commentaires ignorés", function()
    for _index_0 = 1, #result do
      local d = result[_index_0]
      assert(d:sub(1, 1) ~= "#", "commentaire présent : " .. tostring(d))
    end
  end)
end
do
  local text = [[# hosts file
127.0.0.1 localhost
0.0.0.0 ads.example.com
0.0.0.0 0.0.0.0
127.0.0.1 tracking.example.org
::1 ip6-localhost
0.0.0.0 DOUBLECLICK.NET
]]
  local result = parse_hosts(text)
  test("parse_hosts — nombre de domaines extraits (skip localhost/0.0.0.0/::1)", function()
    return assert_eq(#result, 3, "3 domaines")
  end)
  test("parse_hosts — localhost ignoré", function()
    for _index_0 = 1, #result do
      local d = result[_index_0]
      assert(d ~= "localhost", "localhost présent")
    end
  end)
  test("parse_hosts — normalisation minuscules", function()
    local found = false
    for _index_0 = 1, #result do
      local d = result[_index_0]
      if d == "doubleclick.net" then
        found = true
      end
    end
    return assert(found, "doubleclick.net normalisé")
  end)
end
do
  local text = [[! Commentaire adblock
||ads.example.com^
||tracker.example.org^$third-party
@@||whitelist.example.com^
||DOUBLECLICK.NET^
||invalid
##.css-rule
]]
  local result = parse_adblock(text)
  test("parse_adblock — nombre de domaines extraits", function()
    return assert_eq(#result, 3, "3 domaines (pas d'exception @@, pas de CSS)")
  end)
  test("parse_adblock — normalisation minuscules", function()
    local found = false
    for _index_0 = 1, #result do
      local d = result[_index_0]
      if d == "doubleclick.net" then
        found = true
      end
    end
    return assert(found, "doubleclick.net normalisé")
  end)
  test("parse_adblock — exception @@ ignorée", function()
    for _index_0 = 1, #result do
      local d = result[_index_0]
      assert(d ~= "whitelist.example.com", "exception présente")
    end
  end)
end
test("parse — format 'simple' dispatche vers parse_simple", function()
  local result = parse("simple", "example.com\n# commentaire\n")
  assert_eq(#result, 1, "1 domaine")
  return assert_eq(result[1], "example.com", "domaine")
end)
test("parse — format inconnu → parse_simple par défaut", function()
  local result = parse("unknown_format", "example.com\n")
  return assert_eq(#result, 1, "fallback simple")
end)
io.write("\n── load_config ──\n")
local load_config
load_config = require("filter.lib.load_config").load_config
do
  local TMP_YAML = "./tmp/test_filter_config.yml"
  local YAML_OK = [[domainlists_dir: /etc/custos/lists
nets:
  lan:
  - 192.168.0.0/16
times:
  business: ["8:00", "18:00"]
sources:
  ads:
    urls:
    - https://example.com/list.txt
    format: hosts
    subdir: ads
rules:
- description: Règle test
  actions: [allow]
  conditions:
    to_domain: example.com
- description: Refus par défaut
  actions: [deny]
]]
  local fd = io.open(TMP_YAML, "w")
  fd:write(YAML_OK)
  fd:close()
  test("load_config — chargement fichier valide", function()
    local cfg, err = load_config(TMP_YAML)
    return assert(cfg ~= nil, "cfg nil : " .. tostring(err))
  end)
  test("load_config — domainlists_dir", function()
    local cfg, _ = load_config(TMP_YAML)
    assert(cfg, "cfg nil")
    return assert_eq(cfg.domainlists_dir, "/etc/custos/lists", "domainlists_dir")
  end)
  test("load_config — section nets (tableau)", function()
    local cfg, _ = load_config(TMP_YAML)
    assert(cfg, "cfg nil")
    assert(cfg.nets and cfg.nets.lan, "nets.lan absent")
    return assert_eq(cfg.nets.lan[1], "192.168.0.0/16", "nets.lan[1]")
  end)
  test("load_config — section times", function()
    local cfg, _ = load_config(TMP_YAML)
    assert(cfg, "cfg nil")
    assert(cfg.times and cfg.times.business, "times.business absent")
    return assert_eq(cfg.times.business[1], "8:00", "times.business[1]")
  end)
  test("load_config — section sources", function()
    local cfg, _ = load_config(TMP_YAML)
    assert(cfg, "cfg nil")
    assert(cfg.sources and cfg.sources.ads, "sources.ads absent")
    assert_eq(cfg.sources.ads.format, "hosts", "sources.ads.format")
    return assert_eq(cfg.sources.ads.urls[1], "https://example.com/list.txt", "sources.ads.urls[1]")
  end)
  test("load_config — section rules (tableau de tables)", function()
    local cfg, _ = load_config(TMP_YAML)
    assert(cfg, "cfg nil")
    assert_eq(#cfg.rules, 2, "2 règles")
    assert_eq(cfg.rules[1].description, "Règle test", "règle 1 description")
    assert_eq(cfg.rules[1].actions[1], "allow", "règle 1 action")
    return assert_eq(cfg.rules[1].conditions.to_domain, "example.com", "règle 1 condition")
  end)
  test("load_config — sections manquantes → tables vides", function()
    local fd2 = io.open(TMP_YAML, "w")
    fd2:write("rules: []\n")
    fd2:close()
    local cfg, _ = load_config(TMP_YAML)
    assert(cfg, "cfg nil")
    assert(type(cfg.nets) == "table", "nets vide")
    assert(type(cfg.times) == "table", "times vide")
    return assert(type(cfg.sources) == "table", "sources vide")
  end)
  test("load_config — fichier inexistant → nil + erreur", function()
    local cfg, err = load_config("/chemin/inexistant.yml")
    assert(cfg == nil, "cfg devrait être nil")
    return assert(type(err) == "string", "message d'erreur attendu")
  end)
  test("load_config — YAML invalide → nil + erreur", function()
    local fd3 = io.open(TMP_YAML, "w")
    fd3:write("rules: [\nbad yaml unterminated\n")
    fd3:close()
    local cfg, err = load_config(TMP_YAML)
    assert(cfg == nil, "cfg devrait être nil sur YAML invalide")
    return assert(type(err) == "string", "message d'erreur attendu")
  end)
  test("load_config — section auth : valeurs par défaut", function()
    local fd4 = io.open(TMP_YAML, "w")
    fd4:write("rules: []\nauth:\n  secrets: /etc/custos/secrets\n")
    fd4:close()
    local cfg, err = load_config(TMP_YAML)
    assert(cfg ~= nil, "cfg nil : " .. tostring(tostring(err)))
    assert_eq(cfg.auth.port, 33443, "auth.port défaut")
    assert_eq(cfg.auth.captive_port, 33080, "auth.captive_port défaut")
    assert_eq(cfg.auth.session_ttl, 86400, "auth.session_ttl défaut")
    assert_eq(cfg.auth.host, "::", "auth.host défaut")
    assert_eq(cfg.auth.heartbeat_interval, 30, "heartbeat_interval défaut")
    return assert_eq(cfg.auth.idle_timeout, 120, "idle_timeout défaut")
  end)
  test("load_config — section auth : valeurs personnalisées", function()
    local fd5 = io.open(TMP_YAML, "w")
    fd5:write("rules: []\nauth:\n  port: 8443\n  captive_port: 8080\n  session_ttl: 3600\n  idle_timeout: 60\n")
    fd5:close()
    local cfg, err = load_config(TMP_YAML)
    assert(cfg ~= nil, "cfg nil : " .. tostring(tostring(err)))
    assert_eq(cfg.auth.port, 8443, "auth.port personnalisé")
    assert_eq(cfg.auth.captive_port, 8080, "auth.captive_port personnalisé")
    assert_eq(cfg.auth.session_ttl, 3600, "auth.session_ttl personnalisé")
    return assert_eq(cfg.auth.idle_timeout, 60, "auth.idle_timeout personnalisé")
  end)
  os.remove(TMP_YAML)
end
io.write("\n── auth/sessions ──\n")
local serialize, write_sessions, load_sessions, add_session, purge_expired, read_cached
do
  local _obj_0 = require("auth.sessions")
  serialize, write_sessions, load_sessions, add_session, purge_expired, read_cached = _obj_0.serialize, _obj_0.write_sessions, _obj_0.load_sessions, _obj_0.add_session, _obj_0.purge_expired, _obj_0.read_cached
end
local SESS_FILE = "./tmp/test_sessions.lua"
test("auth/sessions — serialize : table vide", function()
  local result = serialize({ })
  assert(result:find("return {", 1, true))
  return assert(result:find("}", 1, true))
end)
test("auth/sessions — serialize : une session", function()
  local sessions = {
    ["10.0.0.1"] = {
      user = "alice",
      expires = 9999,
      heartbeat = nil
    }
  }
  local result = serialize(sessions)
  assert(result:find('"10.0.0.1"', 1, true, "IP présente"))
  assert(result:find('"alice"', 1, true, "user présent"))
  return assert(result:find("expires = 9999", 1, true, "expires présent"))
end)
test("auth/sessions — serialize : session avec heartbeat", function()
  local sessions = {
    ["10.0.0.2"] = {
      user = "bob",
      expires = 8888,
      heartbeat = 7777
    }
  }
  local result = serialize(sessions)
  return assert(result:find("heartbeat = 7777", 1, true, "heartbeat sérialisé"))
end)
test("auth/sessions — write_sessions + load_sessions round-trip", function()
  local sessions = {
    ["192.168.1.10"] = {
      user = "alice",
      expires = 9999999,
      heartbeat = nil
    },
    ["192.168.1.20"] = {
      user = "bob",
      expires = 8888888,
      heartbeat = 111
    }
  }
  local ok, err = write_sessions(sessions, SESS_FILE)
  assert(ok, "write_sessions a échoué : " .. tostring(tostring(err)))
  local loaded = load_sessions(SESS_FILE)
  assert(loaded["192.168.1.10"], "alice absent")
  assert_eq(loaded["192.168.1.10"].user, "alice", "alice.user")
  assert_eq(loaded["192.168.1.10"].expires, 9999999, "alice.expires")
  assert(loaded["192.168.1.20"], "bob absent")
  assert_eq(loaded["192.168.1.20"].heartbeat, 111, "bob.heartbeat")
  return os.remove(SESS_FILE)
end)
test("auth/sessions — load_sessions : fichier absent → table vide", function()
  local result = load_sessions("./tmp/absent_sessions.lua")
  assert(type(result) == "table", "doit retourner une table")
  local count = 0
  for _ in pairs(result) do
    count = count + 1
  end
  return assert_eq(count, 0, "table vide")
end)
test("auth/sessions — load_sessions : fichier corrompu → table vide", function()
  local CORRUPT = "./tmp/corrupt_sessions.lua"
  local fh = io.open(CORRUPT, "w")
  fh:write("THIS IS NOT VALID LUA {\n")
  fh:close()
  local result = load_sessions(CORRUPT)
  assert(type(result) == "table", "doit retourner une table")
  local count2 = 0
  for _ in pairs(result) do
    count2 = count2 + 1
  end
  assert_eq(count2, 0, "table vide sur fichier corrompu")
  return os.remove(CORRUPT)
end)
test("auth/sessions — add_session : crée la session", function()
  local sessions = { }
  add_session(sessions, "10.1.0.1", "charlie", 3600, 0)
  assert(sessions["10.1.0.1"], "session créée")
  assert_eq(sessions["10.1.0.1"].user, "charlie", "user")
  assert(sessions["10.1.0.1"].expires > os.time(), "expires dans le futur")
  return assert_eq(sessions["10.1.0.1"].heartbeat, nil, "heartbeat nil si idle_timeout=0")
end)
test("auth/sessions — add_session : heartbeat si idle_timeout > 0", function()
  local sessions = { }
  add_session(sessions, "10.1.0.2", "diana", 3600, 120)
  assert(sessions["10.1.0.2"].heartbeat ~= nil, "heartbeat non nil")
  return assert(sessions["10.1.0.2"].heartbeat > os.time(), "heartbeat dans le futur")
end)
test("auth/sessions — purge_expired : retire les sessions expirées", function()
  local sessions = {
    ["10.0.0.1"] = {
      user = "old",
      expires = 1
    },
    ["10.0.0.2"] = {
      user = "valid",
      expires = 9999999999
    }
  }
  purge_expired(sessions)
  assert(sessions["10.0.0.1"] == nil, "session expirée purgée")
  return assert(sessions["10.0.0.2"] ~= nil, "session valide conservée")
end)
test("auth/sessions — purge_expired : retire si heartbeat expiré", function()
  local sessions = {
    ["10.0.0.3"] = {
      user = "hb",
      expires = 9999999999,
      heartbeat = 1
    }
  }
  purge_expired(sessions)
  return assert(sessions["10.0.0.3"] == nil, "session avec heartbeat expiré purgée")
end)
io.write("\n── auth/credentials ──\n")
local ok_creds, creds_mod = pcall(require, "auth.credentials")
if not ok_creds then
  io.write("  SKIP (libcrypto non disponible)\n")
else
  local verify_password, hash_password, load_secrets
  verify_password, hash_password, load_secrets = creds_mod.verify_password, creds_mod.hash_password, creds_mod.load_secrets
  local CREDS_FILE = "./tmp/test_secrets"
  test("auth/credentials — verify_password : mot de passe correct", function()
    local stored = hash_password("mysecretpassword")
    assert(type(stored) == "string", "hash_password retourne une string")
    return assert(verify_password("mysecretpassword", stored), "mot de passe correct")
  end)
  test("auth/credentials — verify_password : mauvais mot de passe", function()
    local stored = hash_password("mysecretpassword")
    return assert(not (verify_password("wrongpassword", stored)), "mauvais MdP rejeté")
  end)
  test("auth/credentials — verify_password : hash invalide → faux", function()
    return assert(not (verify_password("anything", "notavalidhash")), "hash invalide → false")
  end)
  test("auth/credentials — verify_password : algo inconnu → faux", function()
    return assert(not (verify_password("pass", "bcrypt:12:salt:hash")), "algo inconnu → false")
  end)
  test("auth/credentials — load_secrets : fichier valide", function()
    local stored_alice = hash_password("alice123")
    local fh = io.open(CREDS_FILE, "w")
    fh:write("# commentaire\n")
    fh:write("alice:" .. tostring(stored_alice) .. "\n")
    fh:write("\n")
    fh:write("bob:pbkdf2-sha256:100000:aabbcc:ddeeff\n")
    fh:close()
    local secrets, err = load_secrets(CREDS_FILE)
    assert(secrets ~= nil, "load_secrets a retourné nil : " .. tostring(tostring(err)))
    assert(secrets["alice"] ~= nil, "alice absent")
    assert(secrets["bob"] ~= nil, "bob absent")
    assert(verify_password("alice123", secrets["alice"]), "alice authentifiable")
    return os.remove(CREDS_FILE)
  end)
  test("auth/credentials — load_secrets : fichier absent → nil + erreur", function()
    local secrets, err = load_secrets("./tmp/absent_secrets")
    assert(secrets == nil, "doit retourner nil")
    return assert(type(err) == "string", "message d'erreur attendu")
  end)
  test("auth/credentials — load_secrets : lignes malformées ignorées", function()
    local fh = io.open(CREDS_FILE, "w")
    fh:write("malformed_line_no_colon\n")
    fh:write("alice:pbkdf2-sha256:100000:aabbcc:ddeeff\n")
    fh:close()
    local secrets, err = load_secrets(CREDS_FILE)
    assert(secrets ~= nil, "load_secrets nil : " .. tostring(tostring(err)))
    assert(secrets["alice"] ~= nil, "alice présent malgré ligne malformée")
    local count_s = 0
    for _ in pairs(secrets) do
      count_s = count_s + 1
    end
    assert_eq(count_s, 1, "une seule entrée valide")
    return os.remove(CREDS_FILE)
  end)
end
io.write("\n── filter/convert ──\n")
local read_bin
read_bin = function(path)
  local fh = io.open(path, "rb")
  if not (fh) then
    return nil
  end
  local data = fh:read("*a")
  fh:close()
  return data
end
local u64_le
u64_le = function(s, i, j)
  for b = 7, 0, -1 do
    local ai = string.byte(s, i * 8 + b + 1)
    local aj = string.byte(s, j * 8 + b + 1)
    if ai < aj then
      return true
    end
    if ai > aj then
      return false
    end
  end
  return true
end
local sorted_u64
sorted_u64 = function(s)
  local n = math.floor(#s / 8)
  if n <= 1 then
    return true
  end
  for i = 0, n - 2 do
    if not (u64_le(s, i, i + 1)) then
      return false
    end
  end
  return true
end
local CONV_INPUT = "./tmp/test_convert.domains"
local CONV_OUTPUT = "./tmp/test_convert.bin"
local run_convert
run_convert = function(args)
  local ok = os.execute("LUA_PATH='lua/?.lua;lua/?/init.lua;;' luajit lua/filter/convert.lua " .. tostring(args) .. " 2>/dev/null")
  return ok == true
end
test("filter/convert — pas d'arguments → exit non nul", function()
  local ok = run_convert("")
  return assert(not ok, "devrait échouer sans arguments")
end)
test("filter/convert — fichier d'entrée absent → exit non nul", function()
  local ok = run_convert("./tmp/__nonexistent__.domains " .. tostring(CONV_OUTPUT))
  return assert(not ok, "devrait échouer avec fichier absent")
end)
test("filter/convert — domaines valides → binaire trié", function()
  local fh = io.open(CONV_INPUT, "w")
  fh:write("github.com\nfacebook.com\ngoogle.com\n")
  fh:close()
  local ok = run_convert(tostring(CONV_INPUT) .. " " .. tostring(CONV_OUTPUT))
  assert(ok, "exit 0 attendu")
  local data = read_bin(CONV_OUTPUT)
  assert(data ~= nil, "fichier de sortie absent")
  assert(#data == 3 * 8, "taille attendue 24 octets (3 hashes × 8)")
  assert(sorted_u64(data), "hashes non triés")
  os.remove(CONV_INPUT)
  return os.remove(CONV_OUTPUT)
end)
test("filter/convert — doublons dédupliqués → un seul hash", function()
  local fh = io.open(CONV_INPUT, "w")
  fh:write("github.com\ngithub.com\ngithub.com\n")
  fh:close()
  local ok = run_convert(tostring(CONV_INPUT) .. " " .. tostring(CONV_OUTPUT))
  assert(ok, "exit 0 attendu")
  local data = read_bin(CONV_OUTPUT)
  assert(data ~= nil, "fichier de sortie absent")
  assert(#data == 8, "un seul hash attendu après déduplication, got " .. tostring(#data) .. " octets")
  os.remove(CONV_INPUT)
  return os.remove(CONV_OUTPUT)
end)
test("filter/convert — commentaires et lignes vides ignorés", function()
  local fh = io.open(CONV_INPUT, "w")
  fh:write("# ce fichier a des commentaires\n")
  fh:write("\n")
  fh:write("github.com  # commentaire inline\n")
  fh:write("   \n")
  fh:close()
  local ok = run_convert(tostring(CONV_INPUT) .. " " .. tostring(CONV_OUTPUT))
  assert(ok, "exit 0 attendu")
  local data = read_bin(CONV_OUTPUT)
  assert(data ~= nil, "fichier de sortie absent")
  assert(#data == 8, "un seul hash attendu (github.com uniquement), got " .. tostring(#data) .. " octets")
  os.remove(CONV_INPUT)
  return os.remove(CONV_OUTPUT)
end)
io.write(string.format("\n%d test(s) passé(s), %d échec(s)\n", passed, failed))
return os.exit(failed == 0 and 0 or 1)
