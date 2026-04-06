-- tests/test_ndpi.moon
-- Tests unitaires pour le parseur nDPI FFI pur (parse/ndpi).
-- Requiert libndpi installé (apt install libndpi-dev).

ffi = require "ffi"
bit = require "bit"

-- ── Mini framework de test ───────────────────────────────────────
passed, failed = 0, 0

test = (name, fn) ->
  ok, err = pcall fn
  if ok
    passed += 1
    io.write string.format("  OK   %s\n", name)
  else
    failed += 1
    io.write string.format("  FAIL %s\n       %s\n", name, tostring err)

assert_eq = (got, expected, msg) ->
  if got ~= expected
    error string.format("%s\n       got:      %s\n       expected: %s",
      msg or "", tostring(got), tostring(expected)), 2

-- ── Packet builders ─────────────────────────────────────────────

ip4bytes = (s) ->
  a, b, c, d = s\match "(%d+)%.(%d+)%.(%d+)%.(%d+)"
  string.char tonumber(a), tonumber(b), tonumber(c), tonumber(d)

make_dns = (qname_encoded, qtype, is_response, txid, ancount) ->
  txid    = txid or 0x1234
  qtype   = qtype or 1
  ancount = ancount or 0
  flags_hi = is_response and 0x81 or 0x01
  flags_lo = 0x00
  -- header: txid(2), flags(2), qdcount=1(2), ancount(2), nscount=0(2), arcount=0(2)
  hdr = string.char(
    bit.rshift(bit.band(txid, 0xFF00), 8), bit.band(txid, 0xFF),
    flags_hi, flags_lo,
    0, 1,
    0, ancount,
    0, 0, 0, 0
  )
  qsection = qname_encoded .. string.char(0, qtype, 0, 1)
  hdr .. qsection

make_ipv4_udp_dns = (src_ip, dst_ip, src_port, dst_port, dns_payload) ->
  total_len = 20 + 8 + #dns_payload
  -- IP header: ver/ihl, dscp, total_len(2), id(2), flags/frag(2), ttl, proto=UDP, cksum(2)
  ip = string.char(
    0x45, 0,
    bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF),
    0, 1,
    0, 0,
    64,
    17,
    0, 0
  ) .. ip4bytes(src_ip) .. ip4bytes(dst_ip)
  udp_len = 8 + #dns_payload
  udp = string.char(
    bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF),
    bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF),
    bit.rshift(bit.band(udp_len,  0xFF00), 8), bit.band(udp_len,  0xFF),
    0, 0
  )
  ip .. udp .. dns_payload

-- Construit un paquet IPv6/UDP/DNS synthétique.
-- src_ip6_bytes et dst_ip6_bytes : 16 octets bruts (Lua string).
make_ipv6_udp_dns = (src_ip6_bytes, dst_ip6_bytes, src_port, dst_port, dns_payload) ->
  udp_len = 8 + #dns_payload
  -- IPv6 fixed header (40 bytes) : version=6, TC=0, flow=0,
  -- payload_len (2B), next_header=17 (UDP), hop_limit=64, src (16B), dst (16B).
  ip6_hdr = string.char(
    0x60, 0x00, 0x00, 0x00,
    bit.rshift(bit.band(udp_len, 0xFF00), 8), bit.band(udp_len, 0xFF),
    17, 64
  )
  ip6 = ip6_hdr .. src_ip6_bytes .. dst_ip6_bytes
  udp = string.char(
    bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF),
    bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF),
    bit.rshift(bit.band(udp_len,  0xFF00), 8), bit.band(udp_len,  0xFF),
    0, 0
  )
  ip6 .. udp .. dns_payload

-- ── Chargement du module nDPI ────────────────────────────────────
io.write "\n── Loading parse/ndpi module ──\n"

-- Injection de la dépendance config.
package.loaded["config"] = {
  PROTO_UDP: 17
  AF_INET:   2
  AF_INET6:  10
  DNS_PORT:  53
  ALLOWED_DOMAINS: {}
  IPC_MSG_SIZE:    21
  IPC_PENDING_TTL: 5
}

-- inet_ntop est nécessaire pour formater les adresses IPv6.
-- pcall : idempotent si déjà déclaré par ffi_defs (même signature).
pcall ffi.cdef, [[ char* inet_ntop(int af, const void *src, char *dst, unsigned int size); ]]

-- La façade ffi_ndpi détecte la version et charge les cdef v4/v5.
package.loaded["ffi_ndpi_v4"] = dofile "lua/ffi_ndpi_v4.lua"
package.loaded["ffi_ndpi_v5"] = dofile "lua/ffi_ndpi_v5.lua"
package.loaded["ffi_ndpi"]    = dofile "lua/ffi_ndpi.lua"
ffi_ndpi = package.loaded["ffi_ndpi"]

-- Chargement du backend spécifique à la version.
package.loaded["parse.ndpi_v4"] = dofile "lua/parse/ndpi_v4.lua"
package.loaded["parse.ndpi_v5"] = dofile "lua/parse/ndpi_v5.lua"
ndpi = dofile "lua/parse/ndpi.lua"

-- ════════════════════════════════════════════════════════════════
-- Tests: détection de version
-- ════════════════════════════════════════════════════════════════
io.write "\n── version detection ──\n"

test "ffi_ndpi — version detected from ndpi_revision()", ->
  assert ffi_ndpi.major, "major is nil"
  assert ffi_ndpi.minor, "minor is nil"
  assert ffi_ndpi.rev,   "rev is nil"
  assert (type(ffi_ndpi.major) == "number"), "major is number"
  assert (type(ffi_ndpi.minor) == "number"), "minor is number"
  assert (ffi_ndpi.major >= 4), "major >= 4, got: " .. ffi_ndpi.major

-- ════════════════════════════════════════════════════════════════
-- Tests: parse_packet
-- ════════════════════════════════════════════════════════════════
io.write "\n── parse_packet ──\n"

test "parse_packet — DNS question A www.github.com", ->
  qname = "\3www\6github\3com\0"
  dns   = make_dns qname, 1, false, 0xABCD
  raw   = make_ipv4_udp_dns "192.168.1.42", "8.8.8.8", 54321, 53, dns
  p     = ndpi.parse_packet raw
  assert p, "parse_packet returned nil"
  -- L3
  assert_eq p.ip.version,  4,              "ip_version"
  assert_eq p.ip.ihl,      20,             "ihl"
  assert_eq p.ip.protocol, 17,             "protocol"
  assert_eq p.ip.src_ip,   "192.168.1.42", "src_ip"
  assert_eq p.ip.dst_ip,   "8.8.8.8",      "dst_ip"
  -- L4
  assert_eq p.udp.src_port, 54321, "src_port"
  assert_eq p.udp.dst_port, 53,    "dst_port"
  -- L7
  assert_eq p.dns.txid,        0xABCD, "txid"
  assert_eq p.dns.is_response, false,   "is_response"
  assert_eq p.dns.qdcount,     1,       "qdcount"
  -- Questions
  assert_eq #p.questions,              1,               "question count"
  assert_eq p.questions[1].qname,      "www.github.com","qname"
  assert_eq p.questions[1].qtype,      1,               "qtype A"
  assert_eq p.questions[1].qtype_name, "A",             "qtype_name"
  -- nDPI detection: master_protocol = DNS (5)
  assert_eq p.ndpi_master, 5, "nDPI master protocol = DNS (5)"

test "parse_packet — nil on too-short packet", ->
  assert_eq ndpi.parse_packet("\x45\x00\x00"), nil, "too short"

test "parse_packet — nil on non-UDP", ->
  -- IP: ver4/ihl5, len=40, id=1, ttl=64, proto=TCP(6), cksum=0
  raw = string.char(0x45, 0, 0, 40, 0, 1, 0, 0, 64, 6, 0, 0) ..
    ip4bytes("1.2.3.4") .. ip4bytes("5.6.7.8") ..
    string.rep("\0", 20)
  assert_eq ndpi.parse_packet(raw), nil, "non-UDP → nil"

test "parse_packet — AAAA question", ->
  qname = "\3www\6github\3com\0"
  dns   = make_dns qname, 28, false, 0x5678
  raw   = make_ipv4_udp_dns "10.0.0.1", "1.1.1.1", 12345, 53, dns
  p     = ndpi.parse_packet raw
  assert p, "parse_packet returned nil"
  assert_eq p.questions[1].qtype,      28,     "qtype AAAA"
  assert_eq p.questions[1].qtype_name, "AAAA", "qtype_name"

test "parse_packet — IPv6 UDP DNS question", ->
  ip6_src = string.char(0x20,0x01, 0x0d,0xb8, 0,0, 0,0, 0,0, 0,0, 0,0, 0,1)
  ip6_dst = string.char(0x20,0x01, 0x0d,0xb8, 0,0, 0,0, 0,0, 0,0, 0,0, 0,2)
  qname = "\3www\6github\3com\0"
  dns   = make_dns qname, 1, false, 0x9ABC
  raw   = make_ipv6_udp_dns ip6_src, ip6_dst, 54321, 53, dns
  p     = ndpi.parse_packet raw
  assert p, "parse_packet IPv6 returned nil"
  assert_eq p.ip.version,  6,   "ip version == 6"
  assert_eq p.ip.ihl,      40,  "ihl == 40"
  assert_eq p.ip.protocol, 17,  "protocol UDP"
  assert_eq p.ip.src_ip, "2001:db8::1", "src_ip"
  assert_eq p.ip.dst_ip, "2001:db8::2", "dst_ip"
  assert_eq p.udp.src_port, 54321, "src_port"
  assert_eq p.udp.dst_port, 53,    "dst_port"
  assert_eq p.dns.txid, 0x9ABC, "txid"
  assert_eq #p.questions, 1, "1 question"
  assert_eq p.questions[1].qname, "www.github.com", "qname"

-- ════════════════════════════════════════════════════════════════
-- Tests: parse_answers
-- ════════════════════════════════════════════════════════════════
io.write "\n── parse_answers ──\n"

test "parse_answers — A record 1.2.3.4", ->
  qname_enc = "\6github\3com\0"
  -- hdr: txid=0x5678, QR=1 RD=1 RA=1, qdcount=1, ancount=1
  hdr = string.char(0x56, 0x78, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  question = qname_enc .. string.char(0, 1, 0, 1)
  -- RR: ptr→offset12 (0xC00C), type A, class IN, TTL=300, rdlen=4, 1.2.3.4
  rr = "\xC0\x0C" ..
    string.char(0, 1, 0, 1) ..
    string.char(0, 0, 1, 0x2C) ..
    string.char(0, 4) ..
    string.char(1, 2, 3, 4)
  dns_payload = hdr .. question .. rr
  raw = make_ipv4_udp_dns "8.8.8.8", "192.168.1.42", 53, 54321, dns_payload
  p   = ndpi.parse_packet raw
  assert p, "parse_packet nil"
  assert_eq p.dns.is_response, true, "is_response"
  answers = ndpi.parse_answers raw, p
  assert_eq #answers,            1,         "1 answer"
  assert_eq answers[1].rdata_str,"1.2.3.4", "rdata_str"
  assert_eq answers[1].rtype,    1,         "rtype A"
  assert_eq answers[1].ttl,      300,       "ttl"

test "parse_answers — CNAME record", ->
  qname_enc  = "\3www\6github\3com\0"
  -- hdr: txid=0x1234, QR=1 RD=1 RA=1, qdcount=1, ancount=1
  hdr = string.char(0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  question   = qname_enc .. string.char(0, 1, 0, 1)
  cname_data = "\6github\6github\2io\0"
  -- RR: ptr→offset12, type CNAME, class IN, TTL=60, rdlen=#cname_data
  rr = "\xC0\x0C" ..
    string.char(0, 5, 0, 1) ..
    string.char(0, 0, 0, 60) ..
    string.char(0, #cname_data) ..
    cname_data
  dns_payload = hdr .. question .. rr
  raw = make_ipv4_udp_dns "8.8.8.8", "10.0.0.1", 53, 9999, dns_payload
  p   = ndpi.parse_packet raw
  assert p, "parse_packet nil"
  answers = ndpi.parse_answers raw, p
  assert_eq #answers,            1,                 "1 answer"
  assert_eq answers[1].rtype,    5,                 "rtype CNAME"
  assert_eq answers[1].rdata_str,"github.github.io","cname rdata"

test "parse_answers — empty on question packet", ->
  qname = "\3www\6github\3com\0"
  dns   = make_dns qname, 1, false, 0x1234
  raw   = make_ipv4_udp_dns "10.0.0.1", "8.8.8.8", 12345, 53, dns
  p     = ndpi.parse_packet raw
  assert p, "parse_packet nil"
  answers = ndpi.parse_answers raw, p
  assert_eq #answers, 0, "no answers in question"

-- ════════════════════════════════════════════════════════════════
-- Tests: patch_and_checksum
-- ════════════════════════════════════════════════════════════════
io.write "\n── patch_and_checksum ──\n"

test "patch_and_checksum — TTL rewritten to 60", ->
  qname_enc = "\6github\3com\0"
  -- hdr: txid=0xAABB, QR=1 RD=1 RA=1, qdcount=1, ancount=1
  hdr = string.char(0xAA, 0xBB, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  question = qname_enc .. string.char(0, 1, 0, 1)
  -- RR: ptr→offset12, type A, class IN, TTL=300, rdlen=4, 10.20.30.40
  rr = "\xC0\x0C" ..
    string.char(0, 1, 0, 1) ..
    string.char(0, 0, 1, 0x2C) ..
    string.char(0, 4) ..
    string.char(10, 20, 30, 40)
  dns_payload = hdr .. question .. rr
  raw = make_ipv4_udp_dns "8.8.8.8", "192.168.1.1", 53, 5555, dns_payload
  p   = ndpi.parse_packet raw
  assert p, "parse_packet nil"
  answers = ndpi.parse_answers raw, p
  assert_eq answers[1].ttl, 300, "original TTL"
  patched = ndpi.patch_and_checksum raw, p, answers, 60
  assert patched, "patch returned nil"
  assert_eq #patched, #raw, "same length"
  -- Re-parse pour vérifier que le TTL a changé.
  p2 = ndpi.parse_packet patched
  assert p2, "re-parse nil"
  a2 = ndpi.parse_answers patched, p2
  assert_eq a2[1].ttl, 60, "patched TTL"

test "patch_and_checksum — IPv6 TTL réécrit à 60 et checksum UDP valide", ->
  -- 2001:db8::1 → 2001:db8::42:1
  ip6_src = string.char(0x20,0x01, 0x0d,0xb8, 0,0, 0,0, 0,0, 0,0, 0,0, 0,1)
  ip6_dst = string.char(0x20,0x01, 0x0d,0xb8, 0,0, 0,0, 0,0, 0,0, 0,0x42, 0,1)
  qname_enc = "\6github\3com\0"
  -- hdr: txid=0xCCDD, QR=1 RD=1 RA=1, qdcount=1, ancount=1
  hdr = string.char(0xCC, 0xDD, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  question = qname_enc .. string.char(0, 1, 0, 1)
  -- RR: ptr→offset12, type A, class IN, TTL=300, rdlen=4, 5.6.7.8
  rr = "\xC0\x0C" ..
    string.char(0, 1, 0, 1) ..
    string.char(0, 0, 1, 0x2C) ..  -- TTL = 300
    string.char(0, 4) ..
    string.char(5, 6, 7, 8)
  dns_payload = hdr .. question .. rr
  raw     = make_ipv6_udp_dns ip6_src, ip6_dst, 53, 12345, dns_payload
  p       = ndpi.parse_packet raw
  assert p, "parse_packet nil"
  assert_eq p.ip.version, 6, "IPv6"
  answers = ndpi.parse_answers raw, p
  assert_eq #answers,        1,   "1 answer"
  assert_eq answers[1].ttl, 300, "original TTL = 300"
  patched = ndpi.patch_and_checksum raw, p, answers, 60
  assert patched, "patch returned nil"
  assert_eq #patched, #raw, "même longueur"
  -- Vérifier que le TTL a été changé.
  p2 = ndpi.parse_packet patched
  assert p2, "re-parse nil"
  a2 = ndpi.parse_answers patched, p2
  assert_eq a2[1].ttl, 60, "patched TTL"
  -- Vérifier que le checksum UDP est non nul (RFC 2460 impose checksum UDP).
  -- IPv6 header = 40 bytes (0-based); UDP checksum = octets 47-48 (1-based).
  cksum_val = bit.bor(
    bit.lshift(string.byte(patched, 47), 8),
    string.byte(patched, 48)
  )
  assert cksum_val ~= 0, "UDP checksum IPv6 non nul (got " .. cksum_val .. ")"

-- ════════════════════════════════════════════════════════════════
-- Nettoyage
-- ════════════════════════════════════════════════════════════════
ndpi.cleanup!

io.write string.format("\n%d test(s) passed, %d failure(s)\n", passed, failed)
os.exit failed == 0 and 0 or 1
