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
  assert_eq(decoded.ip_str, "2001:db8:0:0:0:0:0:1", "ip_str")
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
test("drain_pipe — lit IPC_MSG_SIZE=21 octets sans overflow", function()
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
io.write(string.format("\n%d test(s) passé(s), %d échec(s)\n", passed, failed))
return os.exit(failed == 0 and 0 or 1)
