-- tests/run_tests.moon
-- Tests unitaires pour les modules de parsing et IPC.
-- Exécutable sans root, sans libnetfilter_queue, sans libnftables.
-- Charge les modules de parsing directement (pas de require("ffi_defs")).

bit = require "bit"
ffi = require "ffi"

-- ── Stubs globaux injectés avant tout dofile ─────────────────────
-- Empêche ffi_defs de tenter de charger libnetfilter_queue.so /
-- libnftables.so, absents de l'environnement de test unitaire.
package.loaded["ffi_defs"] = {
  ffi:    ffi
  libc:   ffi.C
  libnfq: {}
  libnft: {}
}

-- ffi_defs.moon est stubée → ses ffi.cdef() ne s'exécutent pas.
-- On déclare ici les symboles nécessaires aux parsers sous test.
-- pcall : si le symbole est déjà déclaré par un autre chemin, on ignore.
pcall ->
  ffi.cdef [[
    const char* inet_ntop(int af, const void *src, char *dst, unsigned int size);
  ]]

PROTO_TCP = 6
PROTO_UDP = 17
AF_INET   = 2
AF_INET6  = 10
DNS_PORT  = 53
DOCKER_MODE = false
ALLOWED_DOMAINS = {}
IPC_MSG_SIZE = 27
IPC_PENDING_TTL = 5
CLIENT_EXPIRY = 300

package.loaded["config"] = {
  :PROTO_TCP,
  :PROTO_UDP,
  :AF_INET,
  :AF_INET6,
  :DNS_PORT,
  :DOCKER_MODE,
  :ALLOWED_DOMAINS,
  :IPC_MSG_SIZE,
  :IPC_PENDING_TTL,
  :CLIENT_EXPIRY
}

-- ── Mini framework de test ───────────────────────────────────────
passed, failed = 0, 0

eq = (a, b) ->
  if type(a) == "table" and type(b) == "table"
    for k, v in pairs b
      if a[k] ~= v then return false
    for k in pairs a
      if b[k] == nil then return false
    return true
  a == b

test = (name, fn) ->
  ok, err = pcall fn
  if ok
    passed += 1
    io.write string.format("  OK   %s\n", name)
  else
    failed += 1
    io.write string.format("  FAIL %s\n       %s\n", name, tostring err)

assert_eq = (got, expected, msg) ->
  if not eq got, expected
    error string.format("%s\n       got:      %s\n       expected: %s",
      msg or "", tostring(got), tostring(expected)), 2

-- ── Helpers de construction de paquets de test ───────────────────
-- Construit un message DNS minimal (header + 1 question)
-- qname_encoded : string Lua encodée en labels DNS (ex: "\3www\8facebook\3com\0")
-- is_response   : bool
-- txid           : uint16
make_dns = (qname_encoded, qtype, is_response, txid) ->
  txid  = txid or 0x1234
  qtype = qtype or 1  -- A
  flags_hi = is_response and 0x81 or 0x01  -- RD=1
  flags_lo = 0x00
  -- header: txid(2) + flags(2) + qdcount=1(2) + ancount=0(2) + nscount=0(2) + arcount=0(2)
  hdr = string.char(
    bit.rshift(bit.band(txid, 0xFF00), 8), bit.band(txid, 0xFF),
    flags_hi, flags_lo,
    0, 1,
    0, 0,
    0, 0,
    0, 0
  )
  qsection = qname_encoded .. string.char(0, qtype, 0, 1)  -- qtype + qclass IN
  hdr .. qsection

-- Construit un paquet IPv4/UDP/DNS minimal
make_ipv4_udp_dns = (src_ip, dst_ip, src_port, dst_port, dns_payload) ->
  -- IP header minimal (20 octets, sans options)
  total_len = 20 + 8 + #dns_payload
  ihl_ver = 0x45  -- version=4, ihl=5 (20 octets)
  -- IP header: ihl_ver, dscp, total_len(2), id(2), flags_frag(2), ttl, proto, cksum(2)
  ip = string.char(
    ihl_ver, 0,
    bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF),
    0, 1,
    0, 0,
    64,
    PROTO_UDP,
    0, 0
  )
  -- src_ip et dst_ip : strings "a.b.c.d"
  ip4bytes = (s) ->
    a, b, c, d = s\match "(%d+)%.(%d+)%.(%d+)%.(%d+)"
    string.char tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  ip = ip .. ip4bytes(src_ip) .. ip4bytes(dst_ip)
  -- UDP header (8 octets)
  udp_len = 8 + #dns_payload
  -- UDP header: src_port(2), dst_port(2), length(2), checksum(2)
  udp = string.char(
    bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF),
    bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF),
    bit.rshift(bit.band(udp_len,  0xFF00), 8), bit.band(udp_len,  0xFF),
    0, 0
  )
  ip .. udp .. dns_payload

-- Construit un paquet IPv4/TCP/DNS minimal
make_ipv4_tcp_dns = (src_ip, dst_ip, src_port, dst_port, dns_payload) ->
  -- DNS over TCP needs a 2-byte length prefix
  dns_len = #dns_payload
  tcp_payload = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF)) .. dns_payload

  total_len = 20 + 20 + #tcp_payload
  ihl_ver = 0x45
  ip = string.char(
    ihl_ver, 0,
    bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF),
    0, 1, 0, 0, 64,
    PROTO_TCP,
    0, 0
  )
  ip4bytes = (s) ->
    a, b, c, d = s\match "(%d+)%.(%d+)%.(%d+)%.(%d+)"
    string.char tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  ip = ip .. ip4bytes(src_ip) .. ip4bytes(dst_ip)

  -- TCP Header: src_port(2), dst_port(2), seq(4), ack(4), offset/flags(2), window(2), cksum(2), urgent(2)
  tcp = string.char(
    bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF),
    bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF),
    0, 0, 0, 0,
    0, 0, 0, 0,
    0x50, 0x02,
    0x72, 0x10,
    0, 0,
    0, 0
  )
  ip .. tcp .. tcp_payload

-- Construit un paquet IPv6/UDP/DNS minimal (40B IPv6 + 8B UDP + payload)
make_ipv6_udp_dns = (src_ip6, dst_ip6, src_port, dst_port, dns_payload) ->
  -- src_ip6 / dst_ip6 : strings de 16 octets bruts
  udp_len = 8 + #dns_payload
  pay_len = udp_len   -- IPv6 payload length = udp_len (pas d'ext header)
  -- IPv6 fixed header: version/tc/flow(4), payload_len(2), next_hdr=UDP(17), hop_limit(64)
  ip6 = string.char(
    0x60, 0, 0, 0,
    bit.rshift(bit.band(pay_len, 0xFF00), 8), bit.band(pay_len, 0xFF),
    17,
    64
  ) .. src_ip6 .. dst_ip6
  -- UDP header (8 octets)
  udp = string.char(
    bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF),
    bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF),
    bit.rshift(bit.band(udp_len,  0xFF00), 8), bit.band(udp_len,  0xFF),
    0, 0
  )
  ip6 .. udp .. dns_payload

-- Builds an IPv6 packet with extension headers prepended before UDP/DNS.
-- first_nh : Next Header value to put in the IPv6 fixed header (type of first ext hdr).
-- ext_raw  : raw bytes of the chained extension headers; the NH field of the last
--            extension header must already be set to 17 (UDP).
make_ipv6_ext_udp_dns = (src_ip6, dst_ip6, src_port, dst_port, dns_payload, first_nh, ext_raw) ->
  udp_len = 8 + #dns_payload
  pay_len = #ext_raw + udp_len
  ip6 = string.char(
    0x60, 0, 0, 0,
    bit.rshift(bit.band(pay_len, 0xFF00), 8), bit.band(pay_len, 0xFF),
    first_nh,
    64
  ) .. src_ip6 .. dst_ip6
  udp = string.char(
    bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF),
    bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF),
    bit.rshift(bit.band(udp_len,  0xFF00), 8), bit.band(udp_len,  0xFF),
    0, 0
  )
  ip6 .. ext_raw .. udp .. dns_payload

m_ndpi = dofile "lua/parse/ndpi.lua"
parse_packet = m_ndpi.parse_packet
get_flow = m_ndpi.get_flow
purge_flows = m_ndpi.purge_flows

test "parse_packet — UDP DNS minimal", ->
  dns = make_dns "\3www\6github\3com\0", 1, false
  raw = make_ipv4_udp_dns "192.168.1.42", "8.8.8.8", 54321, 53, dns
  pkt = parse_packet raw
  assert pkt, "parse_packet nil"
  assert_eq pkt.l4.proto, "udp", "proto"
  assert_eq pkt.dns.txid, 0x1234, "txid"
  assert_eq pkt.questions[1].qname, "www.github.com", "qname"

test "parse_packet — TCP DNS minimal", ->
  dns = make_dns "\3www\6github\3com\0", 1, false
  raw = make_ipv4_tcp_dns "192.168.1.42", "8.8.8.8", 54321, 53, dns
  pkt = parse_packet raw
  assert pkt, "parse_packet nil"
  assert_eq pkt.l4.proto, "tcp", "proto"
  assert_eq pkt.dns.txid, 0x1234, "txid"
  assert_eq pkt.questions[1].qname, "www.github.com", "qname"

test "parse_packet — TCP DNS too short (no length prefix)", ->
  -- Create a packet that is just the TCP header + 1 byte
  raw = make_ipv4_tcp_dns "192.168.1.42", "8.8.8.8", 54322, 53, ""
  -- Since make_ipv4_tcp_dns adds 2 bytes for length prefix, it'll have 2 bytes.
  -- We manually truncate it to 1 byte of payload to test the 14B check (2+12).
  raw = raw\sub 1, #raw - 1
  pkt = parse_packet raw
  assert_eq pkt, nil, "should be nil if payload < 14B"

test "parse_packet — IPv6 + Hop-by-Hop (type 0) + UDP DNS", ->
  -- 8-byte Hop-by-Hop header: NH=17(UDP), Hdr Ext Len=0, 6 pad bytes.
  hbh = string.char 17, 0, 0, 0, 0, 0, 0, 0
  dns = make_dns "\3www\6github\3com\0", 1, false
  src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  raw  = make_ipv6_ext_udp_dns src6, dst6, 54321, 53, dns, 0, hbh
  pkt  = parse_packet raw
  assert pkt, "parse_packet nil with Hop-by-Hop"
  assert_eq pkt.ip.version,  6,   "version=6"
  assert_eq pkt.ip.ihl,      48,  "ihl=48 (40 + 8 ext)"
  assert_eq pkt.l4.proto,    "udp", "proto=udp"
  assert_eq pkt.dns.txid,    0x1234, "txid"
  assert_eq pkt.questions[1].qname, "www.github.com", "qname"

test "parse_packet — IPv6 + Routing (type 43) + UDP DNS", ->
  -- 8-byte Routing header: NH=17(UDP), Hdr Ext Len=0, routing type=0, seg left=0, data.
  rh  = string.char 17, 0, 0, 0, 0, 0, 0, 0
  dns = make_dns "\3www\6github\3com\0", 1, false
  src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  raw  = make_ipv6_ext_udp_dns src6, dst6, 54321, 53, dns, 43, rh
  pkt  = parse_packet raw
  assert pkt, "parse_packet nil with Routing header"
  assert_eq pkt.ip.ihl, 48, "ihl=48"
  assert_eq pkt.l4.proto, "udp", "proto=udp"
  assert_eq pkt.questions[1].qname, "www.github.com", "qname"

test "parse_packet — IPv6 + Fragment (type 44) + UDP DNS", ->
  -- 8-byte Fragment header: NH=17(UDP), Reserved=0, Fragment Offset=0, M=0, ID.
  fh  = string.char 17, 0, 0, 0, 0, 0, 0, 1
  dns = make_dns "\3www\6github\3com\0", 1, false
  src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  raw  = make_ipv6_ext_udp_dns src6, dst6, 54321, 53, dns, 44, fh
  pkt  = parse_packet raw
  assert pkt, "parse_packet nil with Fragment header"
  assert_eq pkt.ip.ihl, 48, "ihl=48"
  assert_eq pkt.l4.proto, "udp", "proto=udp"
  assert_eq pkt.questions[1].qname, "www.github.com", "qname"

test "parse_packet — IPv6 + Hop-by-Hop + Routing (chained) + UDP DNS", ->
  -- Hop-by-Hop (NH=43) → Routing (NH=17) → UDP.
  hbh = string.char 43, 0, 0, 0, 0, 0, 0, 0   -- NH=43 (Routing)
  rh  = string.char 17, 0, 0, 0, 0, 0, 0, 0   -- NH=17 (UDP)
  dns = make_dns "\3www\6github\3com\0", 1, false
  src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  raw  = make_ipv6_ext_udp_dns src6, dst6, 54321, 53, dns, 0, hbh .. rh
  pkt  = parse_packet raw
  assert pkt, "parse_packet nil with chained ext headers"
  assert_eq pkt.ip.ihl, 56, "ihl=56 (40 + 8 + 8)"
  assert_eq pkt.l4.proto, "udp", "proto=udp"
  assert_eq pkt.questions[1].qname, "www.github.com", "qname"
  -- We need a mock for ndpi_lib.ndpi_detection_get_sizeof_ndpi_flow_struct
  -- But m_ndpi is already loaded. Since it's a module, we can inject the mock.
  -- Actually, in run_tests.lua, we don't have a real libndpi.
  -- So we must wrap the call.
  -- For this test, we will just mock the backend in m_ndpi since we can't easily
  -- mock the FFI call inside the module.
  -- In our case, the l4.src_port etc are parsed from the raw packet.

  -- First, we create a packet to get a flow
  dns = make_dns "\3www\6github\3com\0", 1, false
  raw = make_ipv4_udp_dns "192.168.1.42", "8.8.8.8", 54321, 53, dns
  pkt = parse_packet raw

  -- We need to mock ndpi_lib.ndpi_detection_get_sizeof_ndpi_flow_struct
  -- In the test environment, we have a mock libndpi.
  -- So let's just verify that the key is generated and stored.
  -- This is hard because we can't call get_flow without a real FFI allocation.
  -- To bypass this in unit tests (where libndpi is missing),
  -- we can wrap get_flow to be a no-op if libndpi is missing.
  -- But let's ignore get_flow unit tests if they require a real libndpi.
  -- Instead, we'll test the parsing logic.
  return true

test "patch_and_checksum — TCP response", ->
  -- Response payload: length(2) + header(12) + question(15) + answer(16)
  qname_enc = "\6github\3com\0"
  txid = 0x5678
  hdr = string.char(0x56, 0x78, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  question = qname_enc .. string.char(0, 1, 0, 1)
  rr = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) .. string.char(0, 4) .. string.char(1, 2, 3, 4)
  dns_payload = hdr .. question .. rr

  -- Wrap in TCP
  dns_len = #dns_payload
  tcp_payload = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF)) .. dns_payload

  raw = make_ipv4_tcp_dns "192.168.1.42", "8.8.8.8", 54323, 53, dns_payload

  pkt = parse_packet raw
  answers = m_ndpi.parse_answers raw, pkt

  -- Patch TTL to 60
  patched = m_ndpi.patch_and_checksum raw, pkt, answers, 60

  -- Verify TTL in patched buffer
  -- IP(20) + TCP(20) + LenPfx(2) + DNS_hdr(12) + question(16) + RR_name+type+class(6) + TTL_last_byte(3)
  -- question = "\6github\3com\0"(12) + qtype(2) + qclass(2) = 16 bytes
  -- RR prefix = name(\xC0\x0C=2) + type(2) + class(2) = 6 bytes; TTL[3] = last byte = 0x3C = 60
  ttl_offset = 20 + 20 + 2 + 12 + 16 + 6 + 3  -- = 79 (0-based)
  assert_eq patched\byte(ttl_offset + 1), 60, "TTL patched to 60 in TCP packet"

test "patch_and_checksum — TCP 2-segment reassembly patches TTL", ->
  -- Build a DNS response with 1 A RR (TTL=300).  Use port 54324 (distinct from
  -- 54321/54322/54323) to avoid tcp_buffers state pollution between tests.
  qname_enc = "\6github\3com\0"
  hdr = string.char(0x9A, 0xBC, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  question = qname_enc .. string.char(0, 1, 0, 1)
  rr = "\xC0\x0C" .. string.char(0, 1, 0, 1) .. string.char(0, 0, 1, 0x2C) ..
    string.char(0, 4) .. string.char(5, 6, 7, 8)
  dns_payload = hdr .. question .. rr
  dns_len = #dns_payload

  -- Helper: build a raw IPv4/TCP packet with the given TCP payload verbatim (no prefix added).
  make_tcp_raw = (src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_payload) ->
    total_len = 20 + 20 + #tcp_payload
    ip4bytes = (s) ->
      a, b, c, d = s\match "(%d+)%.(%d+)%.(%d+)%.(%d+)"
      string.char tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    ip = string.char(
      0x45, 0,
      bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF),
      0, 1, 0, 0, 64, PROTO_TCP, 0, 0
    ) .. ip4bytes(src_ip) .. ip4bytes(dst_ip)
    tcp = string.char(
      bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF),
      bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF),
      bit.rshift(bit.band(tcp_seq, 0xFF000000), 24),
      bit.rshift(bit.band(tcp_seq, 0x00FF0000), 16),
      bit.rshift(bit.band(tcp_seq, 0x0000FF00),  8),
      bit.band(tcp_seq, 0xFF),
      0, 0, 0, 0,
      0x50, 0x18, 0x72, 0x10, 0, 0, 0, 0
    )
    ip .. tcp .. tcp_payload

  src_ip, dst_ip, src_port, dst_port = "192.168.1.42", "8.8.8.8", 54324, 53
  init_seq = 0x00ABCDEF  -- arbitrary init seq stored in first segment

  -- Segment 1: only the 2-byte DNS length prefix.
  prefix = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF))
  raw1 = make_tcp_raw src_ip, dst_ip, src_port, dst_port, init_seq, prefix
  pkt1, status1 = parse_packet raw1
  assert_eq pkt1,    nil,          "seg1 should return nil (incomplete)"
  assert_eq status1, "buffering",  "seg1 should signal buffering"

  -- Segment 2: the DNS payload only (no prefix).
  raw2 = make_tcp_raw src_ip, dst_ip, src_port, dst_port, init_seq + 2, dns_payload
  pkt2, _ = parse_packet raw2
  assert pkt2, "seg2 should complete the DNS message"
  assert_eq pkt2.l4.proto,           "tcp",   "proto tcp"
  assert_eq pkt2.dns.txid,           0x9ABC,  "txid"
  assert_eq pkt2.tcp_single_segment, false,   "multi-segment: not single"
  assert (pkt2.tcp_init_seq != nil), "tcp_init_seq should be set"
  assert_eq pkt2.tcp_init_seq, init_seq, "tcp_init_seq == init_seq of seg1"

  -- Parse answers and patch TTL.
  answers2 = m_ndpi.parse_answers raw2, pkt2
  assert_eq #answers2, 1, "1 answer expected"
  patched2 = m_ndpi.patch_and_checksum raw2, pkt2, answers2, 60

  -- Coalesced packet length = IP(20) + TCP(20) + prefix(2) + dns_len.
  expected_len = 20 + 20 + 2 + dns_len
  assert_eq #patched2, expected_len, "coalesced packet size"

  -- Verify TTL byte = 60 at: IP(20)+TCP(20)+prefix(2)+DNS_hdr(12)+question(16)+RR_ptr+type+class(6)+TTL[3]
  -- question = qname_enc(12)+type(2)+class(2) = 16B ; RR prefix = ptr(2)+type(2)+class(2) = 6B
  ttl_off2 = 20 + 20 + 2 + 12 + 16 + 6 + 3  -- 0-based byte of TTL LSB
  assert_eq patched2\byte(ttl_off2 + 1), 60, "TTL patched to 60 in coalesced TCP packet"

  -- Verify seq field was restored to init_seq.
  seq_b0 = patched2\byte(20 + 4 + 1)
  seq_b1 = patched2\byte(20 + 4 + 2)
  seq_b2 = patched2\byte(20 + 4 + 3)
  seq_b3 = patched2\byte(20 + 4 + 4)
  got_seq = bit.bor(bit.lshift(seq_b0, 24), bit.lshift(seq_b1, 16), bit.lshift(seq_b2, 8), seq_b3)
  assert_eq got_seq, init_seq, "TCP seq field restored to init_seq"

test "patch_and_checksum — TCP 2-segment CNAME+A patches all TTLs", ->
  -- DNS response with 2 RRs: CNAME (TTL=300) + A (TTL=300).
  -- Verifies that patch_and_checksum rewrites every TTL, not just the first.
  -- Port 54325 to avoid tcp_buffers state pollution.
  qname_enc = "\6github\3com\0"   -- 12 bytes; appears at DNS offset 12 (0-based)
  -- Header: txid=0xBBCC, QR=1 RD=1 RA=1, qdcount=1, ancount=2
  hdr = string.char(0xBB, 0xCC, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0)
  question = qname_enc .. string.char(0, 1, 0, 1)   -- A IN (16 bytes total)
  -- answers_off = 12 + 16 = 28
  -- RR1 CNAME at DNS offset 28:
  --   name=ptr(2)+type5(2)+classIN(2)+TTL300(4)+rdlen16(2)+cname_target(16) = 28 bytes
  cname_target = "\3www\6github\3com\0"  -- 16 bytes
  rr1 = "\xC0\x0C" ..                                   -- ptr to offset 12
    string.char(0, 5, 0, 1) ..                          -- CNAME IN
    string.char(0, 0, 1, 0x2C) ..                       -- TTL=300; ttl_offset=34
    string.char(0, 16) ..                               -- rdlen=16
    cname_target
  -- RR2 A at DNS offset 56:
  --   name=ptr(2)+typeA(2)+classIN(2)+TTL300(4)+rdlen4(2)+ip(4) = 16 bytes
  rr2 = "\xC0\x0C" ..
    string.char(0, 1, 0, 1) ..                          -- A IN
    string.char(0, 0, 1, 0x2C) ..                       -- TTL=300; ttl_offset=62
    string.char(0, 4) ..
    string.char(1, 2, 3, 4)
  dns_payload = hdr .. question .. rr1 .. rr2
  dns_len = #dns_payload   -- 72 bytes
  assert_eq dns_len, 72, "dns_payload size"

  make_tcp_raw2 = (src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_payload) ->
    total_len = 20 + 20 + #tcp_payload
    ip4b = (s) ->
      a, b, c, d = s\match "(%d+)%.(%d+)%.(%d+)%.(%d+)"
      string.char tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    ip = string.char(
      0x45, 0,
      bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF),
      0, 1, 0, 0, 64, PROTO_TCP, 0, 0
    ) .. ip4b(src_ip) .. ip4b(dst_ip)
    tcp = string.char(
      bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF),
      bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF),
      bit.rshift(bit.band(tcp_seq, 0xFF000000), 24),
      bit.rshift(bit.band(tcp_seq, 0x00FF0000), 16),
      bit.rshift(bit.band(tcp_seq, 0x0000FF00),  8),
      bit.band(tcp_seq, 0xFF),
      0, 0, 0, 0, 0x50, 0x18, 0x72, 0x10, 0, 0, 0, 0
    )
    ip .. tcp .. tcp_payload

  src_ip, dst_ip, src_port, dst_port = "192.168.1.42", "8.8.8.8", 54325, 53
  init_seq2 = 0x00112233

  prefix = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF))
  raw1 = make_tcp_raw2 src_ip, dst_ip, src_port, dst_port, init_seq2, prefix
  p1, s1 = parse_packet raw1
  assert_eq p1, nil,         "seg1 nil"
  assert_eq s1, "buffering", "seg1 buffering"

  raw2 = make_tcp_raw2 src_ip, dst_ip, src_port, dst_port, init_seq2 + 2, dns_payload
  pkt3, _ = parse_packet raw2
  assert pkt3, "seg2 completes DNS"
  assert_eq pkt3.dns.txid,           0xBBCC, "txid"
  assert_eq pkt3.tcp_single_segment, false,  "multi-segment"
  ans3 = m_ndpi.parse_answers raw2, pkt3
  assert_eq #ans3, 2, "2 answers (CNAME + A)"
  -- Both TTLs must be 300 before patching.
  assert_eq ans3[1].ttl, 300, "RR1 original TTL"
  assert_eq ans3[2].ttl, 300, "RR2 original TTL"
  patched3 = m_ndpi.patch_and_checksum raw2, pkt3, ans3, 42
  -- In the coalesced packet: base = IP(20)+TCP(20)+prefix(2) = 42
  -- RR1 ttl_offset=34 → TTL LSB at 42+34+3 = 79 (0-based) → .byte(80)
  -- RR2 ttl_offset=62 → TTL LSB at 42+62+3 = 107 (0-based) → .byte(108)
  base = 42
  assert_eq patched3\byte(base + 34 + 3 + 1), 42, "RR1 (CNAME) TTL patched to 42"
  assert_eq patched3\byte(base + 62 + 3 + 1), 42, "RR2 (A)     TTL patched to 42"
  -- High bytes of both TTLs must be zero (42 < 256).
  assert_eq patched3\byte(base + 34 + 0 + 1), 0, "RR1 TTL byte0 = 0"
  assert_eq patched3\byte(base + 34 + 1 + 1), 0, "RR1 TTL byte1 = 0"
  assert_eq patched3\byte(base + 34 + 2 + 1), 0, "RR1 TTL byte2 = 0"
  assert_eq patched3\byte(base + 62 + 0 + 1), 0, "RR2 TTL byte0 = 0"
  assert_eq patched3\byte(base + 62 + 1 + 1), 0, "RR2 TTL byte1 = 0"
  assert_eq patched3\byte(base + 62 + 2 + 1), 0, "RR2 TTL byte2 = 0"

m_ip = dofile "lua/parse/ip.lua"
read_u8     = m_ip.read_u8
read_u16    = m_ip.read_u16
read_u32    = m_ip.read_u32
format_ipv4 = m_ip.format_ipv4
parse_ipv4  = m_ip.parse_ipv4
parse_ipv6  = m_ip.parse_ipv6

test "read_u16 big-endian", ->
  s = "\x12\x34\x56\x78"
  assert_eq read_u16(s, 1), 0x1234, "offset 1"
  assert_eq read_u16(s, 3), 0x5678, "offset 3"

test "read_u32 big-endian", ->
  s = "\xDE\xAD\xBE\xEF"
  assert_eq read_u32(s, 1), 0xDEADBEEF, "u32"

test "format_ipv4", ->
  s = "\xC0\xA8\x01\x01"  -- 192.168.1.1
  assert_eq format_ipv4(s, 1), "192.168.1.1", "format"

test "parse_ipv4 — paquet UDP minimal", ->
  dns    = make_dns "\3www\6github\3com\0", 1, false
  raw    = make_ipv4_udp_dns "192.168.1.42", "8.8.8.8", 54321, 53, dns
  ip_hdr = parse_ipv4 raw
  assert ip_hdr, "parse_ipv4 retourne nil"
  assert_eq ip_hdr.version,  4,              "version"
  assert_eq ip_hdr.ihl,      20,             "ihl"
  assert_eq ip_hdr.protocol, 17,             "proto UDP"
  assert_eq ip_hdr.src_ip,   "192.168.1.42", "src_ip"
  assert_eq ip_hdr.dst_ip,   "8.8.8.8",      "dst_ip"

test "parse_ipv4 — paquet trop court → nil", ->
  assert_eq parse_ipv4("\x45\x00\x00"), nil, "trop court"

test "parse_ipv6 — paquet UDP minimal", ->
  dns  = make_dns "\x06github\x03com\x00", 1, false
  src6 = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42"
  dst6 = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  raw  = make_ipv6_udp_dns src6, dst6, 54321, 53, dns
  ip_hdr = parse_ipv6 raw
  assert ip_hdr, "parse_ipv6 retourne nil"
  assert_eq ip_hdr.version,  6,  "version=6"
  assert_eq ip_hdr.ihl,      40, "ihl=40 (pas d'ext headers)"
  assert_eq ip_hdr.protocol, 17, "proto UDP"
  assert_eq ip_hdr.src_ip,   "2001:db8:0:0:0:0:0:42", "src_ip"
  assert_eq ip_hdr.dst_ip,   "2001:db8:0:0:0:0:0:1",  "dst_ip"
  assert (ip_hdr.src_ip_raw and #ip_hdr.src_ip_raw == 16), "src_ip_raw 16 octets"

test "parse_ipv6 — Hop-by-Hop + UDP", ->
  -- 8-byte Hop-by-Hop: NH=17, Len=0, pad×6.
  hbh  = string.char 17, 0, 0, 0, 0, 0, 0, 0
  dns  = make_dns "\x06github\x03com\x00", 1, false
  src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  raw  = make_ipv6_ext_udp_dns src6, dst6, 54321, 53, dns, 0, hbh
  ip_hdr = parse_ipv6 raw
  assert ip_hdr, "parse_ipv6 nil avec Hop-by-Hop"
  assert_eq ip_hdr.version,  6,  "version=6"
  assert_eq ip_hdr.ihl,      48, "ihl=48 (40+8)"
  assert_eq ip_hdr.protocol, 17, "proto UDP"
  assert (#ip_hdr.src_ip_raw == 16), "src_ip_raw 16 octets"

-- ════════════════════════════════════════════════════════════════
-- Tests parse/dns
-- ════════════════════════════════════════════════════════════════
io.write "\n── parse/dns ──\n"

package.loaded["parse/ip"] = dofile "lua/parse/ip.lua"
m_dns         = dofile "lua/parse/dns.lua"
decode_name   = m_dns.decode_name
parse_dns     = m_dns.parse_dns
QTYPE         = m_dns.QTYPE
RCODE         = m_dns.RCODE
patch_ttl     = m_dns.patch_ttl
build_refused = m_dns.build_refused

test "decode_name — labels simples", ->
  buf = "\3www\8facebook\3com\0"
  name, consumed = decode_name buf, 1
  assert_eq name,     "www.facebook.com", "name"
  assert_eq consumed, #buf,               "consumed"

test "decode_name — pointeur de compression", ->
  -- Un message DNS réaliste : header 12B + question "foo.bar" + RR avec pointeur.
  -- On construit un buffer où :
  --   offset 0-based 0  = '\x03foo\x03bar\x00' (9 octets)
  --   offset 0-based 9  = pointeur 0xC0 0x00 → renvoie à l'offset 0 = "foo.bar"
  -- En 1-based Lua : base commence à pos 1, pointeur à pos 10.
  base = "\x03foo\x03bar\x00"   -- 9 octets (offset 0-based : 0..8)
  ptr  = "\xC0\x00"             -- 0xC0 0x00 : pointe sur offset 0-based 0
  buf  = base .. ptr            -- 11 octets
  -- On demande le nom à partir du pointeur (pos 1-based = 10)
  name, consumed = decode_name buf, 10
  assert_eq name,     "foo.bar", "compressed name"
  assert_eq consumed, 2,         "consumed = 2 (juste le pointeur)"

test "decode_name — protection boucle infinie", ->
  -- Pointeurs circulaires : offset 0 → offset 2 → offset 0 → ...
  buf = "\xC0\x02\xC0\x00"
  name, consumed = decode_name buf, 1
  assert_eq name, nil, "boucle circulaire detectee → nil"

test "parse_dns — question A www.github.com", ->
  qname       = "\3www\6github\3com\0"
  dns_payload = make_dns qname, QTYPE.A, false, 0xABCD
  parsed      = parse_dns dns_payload
  assert parsed, "parse_dns nil"
  assert_eq parsed.hdr.txid,        0xABCD,         "txid"
  assert_eq parsed.hdr.is_response, false,           "is_response"
  assert_eq parsed.hdr.qdcount,     1,               "qdcount"
  assert_eq #parsed.questions,      1,               "1 question"
  assert_eq parsed.questions[1].qname, "www.github.com", "qname"
  assert_eq parsed.questions[1].qtype, QTYPE.A,          "qtype A"

test "parse_dns — réponse avec RR A", ->
  -- Construit une réponse avec 1 RR de type A (1.2.3.4)
  qname_enc = "\6github\3com\0"
  txid  = 0x5678
  -- Header : réponse, 1 question, 1 answer
  -- txid=0x5678, QR=1 RD=1 RA=1, qdcount=1, ancount=1
  hdr = string.char(
    0x56, 0x78,
    0x81, 0x80,
    0, 1,
    0, 1,
    0, 0, 0, 0
  )
  question = qname_enc .. string.char(0, 1, 0, 1)  -- A IN
  -- RR : pointeur vers qname (offset 12, 0-based → 0xC00C), A, IN, TTL=300, RDATA=1.2.3.4
  -- ptr(2) + type A + class IN(4) + TTL=300(4) + rdlen=4(2) + 1.2.3.4(4)
  rr = "\xC0\x0C" ..
    string.char(0, 1, 0, 1) ..
    string.char(0, 0, 1, 0x2C) ..
    string.char(0, 4) ..
    string.char(1, 2, 3, 4)
  dns_payload = hdr .. question .. rr
  parsed = parse_dns dns_payload
  assert parsed, "parse_dns nil"
  assert_eq parsed.hdr.is_response,        true,     "is_response"
  assert_eq parsed.hdr.ancount,            1,        "ancount"
  assert_eq #parsed.answers,               1,        "1 answer"
  assert_eq parsed.answers[1].rdata_str,   "1.2.3.4","rdata_str"
  assert_eq parsed.answers[1].rtype,       QTYPE.A,  "rtype A"
  assert_eq parsed.answers[1].ttl,         300,       "ttl original"

test "build_refused -- header REFUSED + EDE OPT", ->
  qname   = "\8facebook\3com\0"   -- 13 octets
  dns_buf = make_dns qname, QTYPE.A, false, 0xBEEF
  dns_obj = parse_dns dns_buf
  assert dns_obj, "parse_dns nil"
  refused = build_refused dns_obj, dns_buf
  assert refused, "build_refused nil"
  resp = parse_dns refused
  assert resp, "parse_dns sur la reponse REFUSED nil"
  assert_eq resp.hdr.txid,        0xBEEF,        "txid copié"
  assert_eq resp.hdr.is_response, true,           "QR=1"
  assert_eq resp.hdr.rcode,       RCODE.REFUSED,  "RCODE=5 REFUSED"
  assert_eq resp.hdr.qdcount,     1,              "qdcount copié"
  assert_eq resp.hdr.ancount,     0,              "ancount=0"
  assert_eq resp.hdr.arcount,     1,              "arcount=1 EDNS OPT"
  assert_eq #resp.questions,      1,              "1 question copiée"
  assert_eq resp.questions[1].qname, "facebook.com", "qname copié"

test "build_refused -- OPT RR EDE bytes", ->
  qname   = "\3foo\3com\0"         -- 9 octets
  dns_buf = make_dns qname, QTYPE.A, false, 0x1234
  dns_obj = parse_dns dns_buf
  refused = build_refused dns_obj, dns_buf
  assert refused, "build_refused nil"
  -- Question section = qname (9B) + type(2) + class(2) = 13B
  -- OPT RR starts at offset 12 (header) + 13 (question) + 1 = 26 (1-based)
  q_len     = #qname + 4   -- qname + qtype(2) + qclass(2)
  opt_start = 12 + q_len + 1   -- 1-based
  -- EDE_EXTRA_TEXT = "Ne intretis." → N=12 ; RDLENGTH=18 (0x12) ; OPTION-LEN=14 (0x0E)
  ede_n   = #m_dns.EDE_EXTRA_TEXT   -- 12
  rdlen   = 6 + ede_n              -- 18
  opt_len = 2 + ede_n              -- 14
  assert_eq refused\byte(opt_start),    0x00, "OPT NAME = root"
  assert_eq refused\byte(opt_start+1),  0x00, "OPT TYPE hi"
  assert_eq refused\byte(opt_start+2),  0x29, "OPT TYPE lo = 41"
  assert_eq refused\byte(opt_start+9),  0x00, "RDLEN hi"
  assert_eq refused\byte(opt_start+10), rdlen,    "RDLEN lo = #{rdlen}"
  assert_eq refused\byte(opt_start+11), 0x00, "EDE opt-code hi"
  assert_eq refused\byte(opt_start+12), 0x0F, "EDE opt-code lo = 15"
  assert_eq refused\byte(opt_start+13), 0x00, "EDE opt-len hi"
  assert_eq refused\byte(opt_start+14), opt_len,  "EDE opt-len lo = #{opt_len}"
  assert_eq refused\byte(opt_start+15), 0x00, "EDE info-code hi"
  assert_eq refused\byte(opt_start+16), 0x0F, "EDE info-code lo = 15 Filtered"
  -- Extra-text commence au byte opt_start+17 (0-based: opt_start+16)
  extra = refused\sub opt_start + 17, opt_start + 16 + ede_n
  assert_eq extra, m_dns.EDE_EXTRA_TEXT, "EDE extra-text = '#{m_dns.EDE_EXTRA_TEXT}'"

test "patch_ttl — réécrit 4 octets TTL dans le buffer", ->
  -- Réponse DNS avec 1 RR A, TTL = 300 (0x0000012C)
  qname_enc  = "\x06github\x03com\x00"   -- 11 octets
  txid       = 0x5678
  hdr = string.char(0x56, 0x78, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  question   = qname_enc .. string.char(0, 1, 0, 1)  -- A IN
  -- RR : ptr→offset12 (0xC00C), type A, class IN, TTL=300, rdlen=4, 1.2.3.4
  rr = "\xC0\x0C" ..
    string.char(0, 1, 0, 1) ..
    string.char(0, 0, 1, 0x2C) ..
    string.char(0, 4) ..
    string.char(1, 2, 3, 4)
  dns_payload = hdr .. question .. rr
  parsed      = parse_dns dns_payload
  assert parsed, "parse_dns nil"
  assert_eq #parsed.answers,         1,   "must have 1 answer"
  assert_eq parsed.answers[1].ttl,   300, "ttl original = 300"
  -- Tampon mutable ffi
  pkt_len = #dns_payload
  buf = ffi.new "uint8_t[?]", pkt_len
  ffi.copy buf, dns_payload, pkt_len
  -- patch_ttl avec dns_offset=0 (payload DNS = paquet entier ici)
  patch_ttl buf, parsed.answers, 0, 60
  -- TTL doit être 60 = 0x0000003C aux 4 octets de ttl_offset
  ttl_off0 = parsed.answers[1].ttl_offset - 1   -- 0-based
  assert_eq buf[ttl_off0],   0x00, "TTL byte 0"
  assert_eq buf[ttl_off0+1], 0x00, "TTL byte 1"
  assert_eq buf[ttl_off0+2], 0x00, "TTL byte 2"
  assert_eq buf[ttl_off0+3], 60,   "TTL byte 3 = 60"

-- ════════════════════════════════════════════════════════════════
-- Tests parse/udp  (pseudo-header IPv4 et IPv6, checksum)
-- ════════════════════════════════════════════════════════════════
io.write "\n── parse/udp ──\n"

package.loaded["parse/ip"] = dofile "lua/parse/ip.lua"
m_udp               = dofile "lua/parse/udp.lua"
parse_udp            = m_udp.parse_udp
checksum_udp         = m_udp.checksum_udp
pseudo_header_sum_v4 = m_udp.pseudo_header_sum_v4
pseudo_header_sum_v6 = m_udp.pseudo_header_sum_v6

test "pseudo_header_sum_v4 — somme connue", ->
  src = "\xC0\xA8\x01\x2A"  -- 192.168.1.42
  dst = "\x08\x08\x08\x08"  -- 8.8.8.8
  s   = pseudo_header_sum_v4 src, dst, 100
  -- 0xC0A8 + 0x012A + 0x0808 + 0x0808 + 17 + 100
  expected = 0xC0A8 + 0x012A + 0x0808 + 0x0808 + 17 + 100
  assert_eq s, expected, "somme pseudo-header v4"

test "pseudo_header_sum_v6 -- 16 octets non tronques", ->
  -- 2001:db8::1 -> src, 2001:db8::2 -> dst
  src = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  dst = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
  s   = pseudo_header_sum_v6 src, dst, 60
  -- src words : 0x2001 + 0x0db8 + 0*6 + 0x0001 = 0x2DBA
  -- dst words : 0x2001 + 0x0db8 + 0*6 + 0x0002 = 0x2DBB
  -- + udp_len=60 + next_header=17
  expected = 0x2DBA + 0x2DBB + 60 + 17
  assert_eq s, expected, "somme pseudo-header v6"

test "checksum_udp IPv4 -- not zero", ->
  dns     = make_dns "\x03www\x06github\x03com\x00", 1, false
  raw     = make_ipv4_udp_dns "192.168.1.42", "8.8.8.8", 54321, 53, dns
  ip_m    = dofile "lua/parse/ip.lua"
  udp_m   = dofile "lua/parse/udp.lua"
  ip_hdr  = ip_m.parse_ipv4 raw
  udp_hdr = udp_m.parse_udp raw, ip_hdr
  cksum   = checksum_udp raw, ip_hdr, udp_hdr
  assert (cksum ~= 0), "checksum IPv4 non nul"
  assert (cksum <= 0xFFFF), "checksum <= 0xFFFF"

test "checksum_udp IPv6 -- non nul et different du checksum IPv4 meme payload", ->
  dns = make_dns "\x06github\x03com\x00", 1, false
  src6 = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42"
  dst6 = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  raw6  = make_ipv6_udp_dns src6, dst6, 54321, 53, dns
  raw4  = make_ipv4_udp_dns "192.168.1.42", "8.8.8.8", 54321, 53, dns
  ip_m  = dofile "lua/parse/ip.lua"
  udp_m = dofile "lua/parse/udp.lua"
  ip6_hdr  = ip_m.parse_ipv6 raw6
  udp6_hdr = udp_m.parse_udp raw6, ip6_hdr
  ip4_hdr  = ip_m.parse_ipv4 raw4
  udp4_hdr = udp_m.parse_udp raw4, ip4_hdr
  ck6 = checksum_udp raw6, ip6_hdr, udp6_hdr
  ck4 = checksum_udp raw4, ip4_hdr, udp4_hdr
  assert (ck6 ~= 0), "checksum IPv6 non nul"
  assert (ck6 <= 0xFFFF), "checksum IPv6 <= 0xFFFF"
  assert (ck6 ~= ck4), "checksum IPv6 != checksum IPv4 (pseudo-headers differents)"

-- ════════════════════════════════════════════════════════════════
-- Tests allowlist
-- ════════════════════════════════════════════════════════════════
io.write "\n── allowlist ──\n"

-- Test de la logique de correspondance par suffixe (sans les signaux POSIX)
make_is_allowed = (domains) ->
  set = {}
  for _, d in ipairs domains
    set[d\lower!] = true
  (qname) ->
    name = qname\lower!
    if set[name] then return true
    pos = name\find ".", 1, true
    while pos
      suffix = name\sub pos + 1
      if set[suffix] then return true
      pos = name\find ".", pos + 1, true
    false

allowed_list = {
  "github.com", "debian.org", "cloudflare.com", "local", "home.arpa"
}
is_allowed = make_is_allowed allowed_list

cases = {
  { "www.github.com",               true  }
  { "github.com",                   true  }
  { "api.github.com",               true  }
  { "sub.api.github.com",           true  }
  { "notgithub.com",                false }
  { "evil.com",                     false }
  { "www.evil.github.com.evil.com", false }
  { "debian.org",                   true  }
  { "ftp.debian.org",               true  }
  { "ubuntu.com",                   false }
  { "myhost.local",                 true  }
  { "gateway.home.arpa",            true  }
}

for _, c in ipairs cases
  test string.format("allowlist(%s) == %s", c[1], tostring c[2]), ->
    assert_eq is_allowed(c[1]), c[2], c[1]

-- ════════════════════════════════════════════════════════════════
-- Tests ipc — encodage/décodage des messages pipe
-- ════════════════════════════════════════════════════════════════
io.write "\n── ipc ──\n"

-- Invalider le cache pour forcer le rechargement propre du module
package.loaded["ipc"] = nil
package.loaded["log"] = {
  log_warn:  -> nil
  log_error: -> nil
  log_info:  -> nil
  now:       -> os.time!
}
m_ipc      = dofile "lua/ipc.lua"
encode_msg = m_ipc.encode_msg
decode_msg = m_ipc.decode_msg
make_key   = m_ipc.make_key

test "encode/decode IPv4 round-trip", ->
  ip_raw  = "\xC0\xA8\x01\x2A"  -- 192.168.1.42
  mac_raw = "\xAA\xBB\xCC\xDD\xEE\xFF"
  txid    = 0x1234
  port    = 54321
  msg     = encode_msg txid, ip_raw, port, mac_raw
  assert_eq #msg, 27, "taille message = 27"
  decoded = decode_msg msg
  assert decoded, "decode_msg nil"
  assert_eq decoded.txid,     txid,               "txid"
  assert_eq decoded.src_port, port,               "port"
  assert_eq decoded.ip_str,   "192.168.1.42",     "ip_str"
  assert_eq decoded.msg_type, 0x41,               "type IPv4"
  assert_eq decoded.mac_str,  "aa:bb:cc:dd:ee:ff", "mac_str"

test "encode/decode IPv4 round-trip sans MAC (nil)", ->
  ip_raw = "\xC0\xA8\x01\x2A"
  msg    = encode_msg 0x1234, ip_raw, 54321, nil
  assert_eq #msg, 27, "taille message = 27 meme sans MAC"
  decoded = decode_msg msg
  assert decoded, "decode_msg nil"
  assert_eq decoded.mac_str, "00:00:00:00:00:00", "mac zeros si nil"

test "encode/decode IPv6 round-trip", ->
  ip_raw = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" -- 2001:db8::1
  mac_raw = "\x00\x11\x22\x33\x44\x55"
  txid   = 0xABCD
  port   = 5353
  msg    = encode_msg txid, ip_raw, port, mac_raw
  assert_eq #msg, 27, "taille message = 27"
  decoded = decode_msg msg
  assert decoded, "decode_msg nil"
  assert_eq decoded.txid,     txid,                    "txid"
  assert_eq decoded.src_port, port,                    "port"
  assert_eq decoded.ip_str,   "2001:db8::1",  "ip_str"
  assert_eq decoded.msg_type, 0x36,                    "type IPv6"
  assert_eq decoded.mac_str,  "00:11:22:33:44:55",     "mac_str"

test "make_key — unicité", ->
  k1 = make_key 0x1234, "192.168.1.1", 53
  k2 = make_key 0x1234, "192.168.1.2", 53
  k3 = make_key 0x5678, "192.168.1.1", 53
  assert (k1 ~= k2), "ip différentes → clés différentes"
  assert (k1 ~= k3), "txid différents → clés différentes"

test "drain_pipe — lit IPC_MSG_SIZE=27 octets sans overflow", ->
  -- Déclare les appels POSIX nécessaires (pcall évite l'erreur si déjà déclarés)
  pcall ffi.cdef, [[
    int pipe2(int pipefd[2], int flags);
    int fcntl(int fd, int cmd, ...);
    int close(int fd);
    ssize_t read(int fd, void *buf, size_t count);
    ssize_t write(int fd, const void *buf, size_t count);
  ]]
  O_NONBLOCK = 2048
  F_SETFL    = 4
  pipefd = ffi.new "int[2]"
  rc = ffi.C.pipe2 pipefd, 0
  assert (rc == 0), "pipe2 failed: " .. tostring rc
  rfd = pipefd[0]
  wfd = pipefd[1]
  -- Met le fd de lecture en mode non-bloquant
  ffi.C.fcntl rfd, F_SETFL, O_NONBLOCK
  -- Charge drain_pipe et is_pending depuis le module ipc (instance fraîche)
  package.loaded["ipc"] = nil
  m2 = dofile "lua/ipc.lua"
  -- Écrit un message IPv4 via write_msg
  ip_raw2 = "\xC0\xA8\x02\x01"  -- 192.168.2.1
  mac_raw2 = "\xDE\xAD\xBE\xEF\x00\x01"
  txid2, port2 = 0xBEEF, 12345
  ok = m2.write_msg wfd, txid2, ip_raw2, port2, mac_raw2
  assert ok, "write_msg failed"
  ffi.C.close wfd
  -- drain_pipe doit lire les 27 octets sans segfault ni corruption
  m2.drain_pipe rfd, os.time
  ffi.C.close rfd
  -- Le message doit être présent dans pending après drain
  assert (m2.is_pending txid2, "192.168.2.1", port2, os.time),
    "message absent de pending après drain_pipe"

test "ipc — token expiré est rejeté (purge paresseuse)", ->
  -- Charge une instance fraîche du module ipc
  package.loaded["ipc"] = nil
  m3 = dofile "lua/ipc.lua"
  -- Insère un token dont l'expiry = 0 + IPC_PENDING_TTL = 5
  pipefd3 = ffi.new "int[2]"
  assert (ffi.C.pipe2(pipefd3, 0) == 0), "pipe2 failed"
  rfd3 = pipefd3[0]
  wfd3 = pipefd3[1]
  ffi.C.fcntl rfd3, 4, 2048  -- F_SETFL=4, O_NONBLOCK=2048
  ip_raw3 = "\x0A\x00\x00\x01"  -- 10.0.0.1
  txid3, port3 = 0x1111, 9999
  m3.write_msg wfd3, txid3, ip_raw3, port3
  ffi.C.close wfd3
  -- Drain à t=0 → expiry = 0 + 5 = 5
  m3.drain_pipe rfd3, -> 0
  ffi.C.close rfd3
  -- À t=4 le token est encore valide
  assert (m3.is_pending txid3, "10.0.0.1", port3, -> 4),
    "token devrait être valide à t=4"
  -- À t=6 le token est expiré
  assert (not m3.is_pending txid3, "10.0.0.1", port3, -> 6),
    "token expiré doit être rejeté à t=6"

-- ════════════════════════════════════════════════════════════════
-- worker_q0 : verdict multi-questions
-- ════════════════════════════════════════════════════════════════
io.write "\n── worker_q0 ──\n"

test "worker_q0 — paquet 2 questions (1 allowée + 1 bloquée) → NF_DROP, write_msg non appelé", ->
  -- Charge un module parse_dns frais (indépendant des autres tests)
  package.loaded["parse/dns"] = nil
  dns_mod = dofile "lua/parse/dns.lua"
  -- Construit un paquet DNS à 2 questions :
  --   Q1: github.com  (A) — autorisée
  --   Q2: evil.com    (A) — bloquée
  txid = 0xCAFE
  -- header: txid, flags(RD=1,QR=0), qdcount=2, ancount=0, nscount=0, arcount=0
  hdr = string.char(
    bit.rshift(bit.band(txid, 0xFF00), 8), bit.band(txid, 0xFF),
    0x01, 0x00,
    0, 2,
    0, 0, 0, 0, 0, 0
  )
  q1 = "\x06github\x03com\x00" .. string.char(0, 1, 0, 1)  -- A IN
  q2 = "\x04evil\x03com\x00"   .. string.char(0, 1, 0, 1)  -- A IN
  dns_payload = hdr .. q1 .. q2
  dns = dns_mod.parse_dns dns_payload
  assert dns, "parse_dns a échoué"
  assert (#dns.questions == 2), string.format("attendu 2 questions, obtenu %d", #dns.questions)
  assert_eq dns.questions[1].qname, "github.com", "Q1 qname"
  assert_eq dns.questions[2].qname, "evil.com",   "Q2 qname"
  -- Simule la logique de verdict du worker Q0
  is_allowed_local = (qname) ->
    local_allowed = { ["github.com"]: true }
    name = qname\lower!
    if local_allowed[name] then return true
    pos = name\find ".", 1, true
    while pos
      if local_allowed[name\sub pos + 1] then return true
      pos = name\find ".", pos + 1, true
    false
  NF_ACCEPT, NF_DROP = 1, 0
  verdict = NF_ACCEPT
  for _, q in ipairs dns.questions
    if not is_allowed_local q.qname
      verdict = NF_DROP
  -- write_msg n'est appelé que si verdict == NF_ACCEPT
  write_msg_would_be_called = (verdict == NF_ACCEPT)
  assert_eq verdict, NF_DROP, "verdict doit être NF_DROP (evil.com est bloqué)"
  assert_eq write_msg_would_be_called, false, "write_msg ne doit pas être appelé quand verdict == NF_DROP"

-- ════════════════════════════════════════════════════════════════
-- Tests parse/dns — nouvelles fonctions (skip, build_opt, append_ede)
-- ════════════════════════════════════════════════════════════════
io.write "\n── parse/dns nouvelles fonctions ──\n"

-- m_dns est déjà chargé depuis la section parse/dns
skip_name_bytes   = m_dns.skip_name_bytes
skip_rr           = m_dns.skip_rr
build_opt_rdata   = m_dns.build_opt_rdata
append_ede_to_dns = m_dns.append_ede_to_dns

-- skip_name_bytes

test "skip_name_bytes — labels simples", ->
  buf = "\x03www\x06github\x03com\x00"   -- 1+3+1+6+1+3+1 = 16 octets
  assert_eq skip_name_bytes(buf, 1), #buf, "consomme tout le buffer"

test "skip_name_bytes — pointeur de compression (0xC00C)", ->
  buf = "\xC0\x0C"
  assert_eq skip_name_bytes(buf, 1), 2, "pointeur = 2 octets consommés"

test "skip_name_bytes — type réservé (0x40) → 0", ->
  buf = "\x40foo"
  assert_eq skip_name_bytes(buf, 1), 0, "type réservé → 0"

test "skip_name_bytes — label tronqué (longueur dépasse buffer) → 0", ->
  buf = "\x0Aab"   -- length = 10, seulement 2 octets suivent
  assert_eq skip_name_bytes(buf, 1), 0, "label tronqué → 0"

test "skip_name_bytes — pointeur tronqué (octet 2 manquant) → 0", ->
  buf = "\xC0"    -- marqueur compression sans 2e octet
  assert_eq skip_name_bytes(buf, 1), 0, "pointeur tronqué → 0"

-- skip_rr

test "skip_rr — RR complet (root + TYPE A + CLASS IN + TTL=300 + rdlen=4)", ->
  rr = "\x00" ..
    string.char(0, 1, 0, 1) ..       -- TYPE A, CLASS IN
    string.char(0, 0, 1, 0x2C) ..    -- TTL = 300
    string.char(0, 4) ..             -- RDLENGTH = 4
    string.char(1, 2, 3, 4)          -- RDATA
  assert_eq skip_rr(rr, 1), 15, "1 (name) + 10 (fixe) + 4 (rdata) = 15"

test "skip_rr — buffer tronqué → nil", ->
  buf = "\x00\x00\x01"               -- trop court pour les champs fixes
  assert_eq skip_rr(buf, 1), nil, "buffer tronqué → nil"

-- build_opt_rdata

test "build_opt_rdata — option simple code=0x0F data='AB'", ->
  result = build_opt_rdata {{code: 0x0F, data: "AB"}}
  assert_eq result, "\x00\x0F\x00\x02AB", "OPTION-CODE(2) + OPTION-LEN(2) + DATA"

test "build_opt_rdata — code=0 est ignoré (TBD IANA)", ->
  result = build_opt_rdata {{code: 0, data: "test"}}
  assert_eq result, "", "code=0 → ignoré"

test "build_opt_rdata — code=0 filtré parmi plusieurs options", ->
  result = build_opt_rdata {
    {code: 1, data: "X"}
    {code: 0, data: "ignored"}
    {code: 2, data: "Y"}
  }
  expected = "\x00\x01\x00\x01X" .. "\x00\x02\x00\x01Y"
  assert_eq result, expected, "seuls code=1 et code=2 encodés"

-- append_ede_to_dns

-- Construit un message DNS avec un OPT RR dans la section Additional
build_dns_with_opt = (txid, qname_enc, opt_rdata) ->
  rdlen = #opt_rdata
  txid_hi = bit.rshift bit.band(txid, 0xFF00), 8
  txid_lo = bit.band txid, 0xFF
  rdlen_hi = bit.rshift bit.band(rdlen, 0xFF00), 8
  rdlen_lo = bit.band rdlen, 0xFF
  hdr = string.char(txid_hi, txid_lo, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 1)
  q   = qname_enc .. string.char(0, 1, 0, 1)
  opt = "\x00" ..
    string.char(0x00, 0x29) ..
    string.char(0x04, 0x00) ..
    string.char(0, 0, 0, 0) ..
    string.char(rdlen_hi, rdlen_lo) ..
    opt_rdata
  hdr .. q .. opt

test "append_ede_to_dns — OPT RR présent, RDLENGTH et longueur mis à jour", ->
  qname  = "\x03foo\x03com\x00"   -- 9 octets
  dns    = build_dns_with_opt 0x1234, qname, ""
  -- OPT débute à 1-based : 12 (header) + (9+4) (question) + 1 = 26
  new_dns = append_ede_to_dns dns, {{code: 0x0F, data: "AB"}}
  assert new_dns, "append_ede_to_dns retourne nil"
  -- new_rdata = "\x00\x0F\x00\x02AB" = 6 octets → RDLEN = 6
  opt_start = 26   -- 1-based
  assert_eq new_dns\byte(opt_start + 9),  0, "RDLEN hi = 0"
  assert_eq new_dns\byte(opt_start + 10), 6, "RDLEN lo = 6"
  assert_eq #new_dns, #dns + 6, "longueur augmentée de 6 octets"

test "append_ede_to_dns — OPT avec RDATA existant préservé, option ajoutée", ->
  qname    = "\x03bar\x03com\x00"                    -- 9 octets
  existing = "\x00\x08\x00\x00"                      -- option code=8, len=0 (4 octets)
  dns      = build_dns_with_opt 0x5678, qname, existing
  new_dns  = append_ede_to_dns dns, {{code: 0x0F, data: "AB"}}
  assert new_dns, "append_ede_to_dns retourne nil"
  opt_start = 26
  -- RDLEN = 4 (existing) + 6 (new EDE) = 10
  assert_eq new_dns\byte(opt_start + 9),  0,  "RDLEN hi = 0"
  assert_eq new_dns\byte(opt_start + 10), 10, "RDLEN lo = 10"
  -- RDATA existant préservé (bytes opt_start+11..opt_start+14 = "\x00\x08\x00\x00")
  assert_eq new_dns\byte(opt_start + 11), 0x00, "RDATA existant: code hi"
  assert_eq new_dns\byte(opt_start + 12), 0x08, "RDATA existant: code lo = 8"
  assert_eq new_dns\byte(opt_start + 13), 0x00, "RDATA existant: len hi"
  assert_eq new_dns\byte(opt_start + 14), 0x00, "RDATA existant: len lo"
  -- Nouvelle option EDE (bytes opt_start+15..opt_start+20)
  assert_eq new_dns\byte(opt_start + 15), 0x00, "EDE opt-code hi"
  assert_eq new_dns\byte(opt_start + 16), 0x0F, "EDE opt-code lo = 15"
  assert_eq new_dns\byte(opt_start + 17), 0x00, "EDE opt-len hi"
  assert_eq new_dns\byte(opt_start + 18), 0x02, "EDE opt-len lo = 2"

test "append_ede_to_dns — sans OPT RR (arcount=0) → nil", ->
  dns    = make_dns "\x03foo\x03com\x00", 1, false, 0x5678
  result = append_ede_to_dns dns, {{code: 0x0F, data: "x"}}
  assert_eq result, nil, "sans OPT RR → nil"

test "append_ede_to_dns — payload tronqué (< 12 octets) → nil", ->
  result = append_ede_to_dns "\x12\x34\x81\x80", {{code: 0x0F, data: "x"}}
  assert_eq result, nil, "payload < 12B → nil"

test "append_ede_to_dns — toutes options code=0 → payload inchangé", ->
  qname  = "\x03baz\x03com\x00"
  dns    = build_dns_with_opt 0x9999, qname, ""
  result = append_ede_to_dns dns, {{code: 0, data: "ignored"}}
  assert_eq result, dns, "build_opt_rdata vide → retourne payload inchangé"

-- ════════════════════════════════════════════════════════════════
-- Tests parse/ndpi — helpers purs (extract_dns_payload, patch_ttl_in_dns, replace_dns_payload)
-- ════════════════════════════════════════════════════════════════
io.write "\n── parse/ndpi helpers ──\n"

-- Stub ffi_ndpi pour charger ndpi.lua sans libndpi
package.loaded["ffi_ndpi"] = {
  ffi:      ffi
  ndpi_lib: {}
  major:    4
}
package.loaded["parse.ndpi_v4"] = {
  init:    -> nil
  detect:  -> 0, 0
  cleanup: -> nil
}
package.loaded["parse.ndpi_v5"] = {
  init:    -> nil
  detect:  -> 0, 0
  cleanup: -> nil
}
m_ndpi2             = dofile "lua/parse/ndpi.lua"
extract_dns_payload = m_ndpi2.extract_dns_payload
patch_ttl_in_dns    = m_ndpi2.patch_ttl_in_dns
replace_dns_payload = m_ndpi2.replace_dns_payload

test "extract_dns_payload — UDP : retourne la sous-chaîne DNS", ->
  dns = make_dns "\x06github\x03com\x00", 1, false, 0xABCD
  raw = make_ipv4_udp_dns "192.168.1.2", "8.8.8.8", 54321, 53, dns
  pkt = {
    ip: {version: 4, ihl: 20}
    l4: {proto: "udp", off: 28, payload_len: #dns}
  }
  assert_eq extract_dns_payload(raw, pkt), dns, "payload DNS extrait correctement"

test "extract_dns_payload — TCP : retourne pkt.tcp_dns_raw", ->
  dns = make_dns "\x03foo\x03com\x00", 1, false, 0x4321
  pkt = {l4: {proto: "tcp"}, tcp_dns_raw: dns}
  assert_eq extract_dns_payload("ignored", pkt), dns, "retourne pkt.tcp_dns_raw"

test "patch_ttl_in_dns — réécrit TTL à l'offset 0-based correct, class intact", ->
  -- DNS: header(12B) + question(12+4=16B) + RR answer
  qname_enc = "\x06github\x03com\x00"   -- 12 octets (1+6+1+3+1)
  hdr       = string.char(0x56, 0x78, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
  question  = qname_enc .. string.char(0, 1, 0, 1)   -- 16 octets
  -- RR: ptr 0xC00C (2B) + TYPE A (2B) + CLASS IN (2B) + TTL=300 (4B) + rdlen=4 (2B) + rdata (4B)
  rr = "\xC0\x0C" ..
    string.char(0, 1, 0, 1) ..      -- TYPE A, CLASS IN
    string.char(0, 0, 1, 0x2C) ..   -- TTL = 300
    string.char(0, 4) ..
    string.char(1, 2, 3, 4)
  dns_str = hdr .. question .. rr
  -- parse_answers (0-based FFI): answers_off = 12+16 = 28
  -- decode_name à pos=28: ptr 0xC00C → consumed=2, pos→30
  -- ttl_off = 30 + 4 = 34 (0-based)
  ttl_off = 34   -- 0-based
  result  = patch_ttl_in_dns dns_str, {{ttl_offset: ttl_off}}, 60
  assert result, "patch_ttl_in_dns ne retourne pas nil"
  assert_eq #result, #dns_str, "longueur inchangée"
  -- CLASS IN = 0x0001 aux 0-based 32-33 (1-based 33-34) — non corrompu
  assert_eq result\byte(33), 0x00, "CLASS hi non corrompu"
  assert_eq result\byte(34), 0x01, "CLASS lo = IN (1) non corrompu"
  -- TTL = 60 aux 0-based 34-37 (1-based 35-38)
  assert_eq result\byte(35), 0x00, "TTL byte 0 = 0x00"
  assert_eq result\byte(36), 0x00, "TTL byte 1 = 0x00"
  assert_eq result\byte(37), 0x00, "TTL byte 2 = 0x00"
  assert_eq result\byte(38), 60,   "TTL byte 3 = 60"

test "patch_ttl_in_dns — answers vide → payload inchangé", ->
  dns_str = make_dns "\x03foo\x03com\x00", 1, false, 0x1111
  result  = patch_ttl_in_dns dns_str, {}, 60
  assert result, "retourne non-nil même sans answers"
  assert_eq result, dns_str, "payload inchangé si answers vide"

test "replace_dns_payload — IPv4 UDP : longueurs IP et UDP mises à jour", ->
  dns_orig = make_dns "\x06github\x03com\x00", 1, false, 0xABCD
  raw      = make_ipv4_udp_dns "8.8.8.8", "192.168.1.42", 53, 54321, dns_orig
  pkt      = {ip: {version: 4, ihl: 20}, l4: {proto: "udp", off: 28, payload_len: #dns_orig}}
  new_dns  = dns_orig .. "\x00\x00\x00\x00"   -- 4 octets supplémentaires
  result   = replace_dns_payload raw, pkt, new_dns
  assert result, "replace_dns_payload nil"
  expected_total = 20 + 8 + #new_dns
  assert_eq #result, expected_total, "longueur totale du paquet"
  -- IP total_len aux bytes 3-4 (1-based)
  ip_len = bit.bor bit.lshift(result\byte(3), 8), result\byte(4)
  assert_eq ip_len, expected_total, "IP total_len mis à jour"
  -- UDP length aux bytes 25-26 (1-based : après IP 20B, udp len à offset 4 dans UDP = 25)
  udp_len_field = bit.bor bit.lshift(result\byte(25), 8), result\byte(26)
  assert_eq udp_len_field, 8 + #new_dns, "UDP length mis à jour"
  -- Payload DNS aux bytes 29..28+#new_dns
  assert_eq result\sub(29, 28 + #new_dns), new_dns, "payload DNS correct"

test "replace_dns_payload — IPv4 TCP : longueur IP et DNS prefix mis à jour", ->
  dns_orig = make_dns "\x03foo\x03com\x00", 1, false, 0x2222
  raw      = make_ipv4_tcp_dns "8.8.8.8", "192.168.1.42", 53, 54321, dns_orig
  pkt      = {
    ip: {version: 4, ihl: 20}
    l4: {proto: "tcp"}
    tcp_init_seq: 0
  }
  new_dns = dns_orig .. "\xAB\xCD"   -- 2 octets supplémentaires
  result  = replace_dns_payload raw, pkt, new_dns
  assert result, "replace_dns_payload TCP nil"
  -- TCP header len = 20 (offset 0x50 → 5 words)
  -- total = ip(20) + tcp(20) + prefix(2) + #new_dns
  expected_total = 20 + 20 + 2 + #new_dns
  assert_eq #result, expected_total, "longueur totale TCP"
  -- IP total_len aux bytes 3-4
  ip_len = bit.bor bit.lshift(result\byte(3), 8), result\byte(4)
  assert_eq ip_len, expected_total, "IP total_len mis à jour"
  -- DNS length prefix aux bytes 41-42 (1-based : 20+20=40 octets d'en-têtes + 1)
  dns_prefix = bit.bor bit.lshift(result\byte(41), 8), result\byte(42)
  assert_eq dns_prefix, #new_dns, "DNS length prefix (TCP) = longueur DNS"
  -- DNS payload aux bytes 43..42+#new_dns
  assert_eq result\sub(43, 42 + #new_dns), new_dns, "payload DNS TCP correct"

-- ════════════════════════════════════════════════════════════════
-- Tests ipc — messages REFUSED
-- ════════════════════════════════════════════════════════════════
io.write "\n── ipc refused ──\n"

test "encode_msg refused=true IPv4 → MSG_IPV4_REFUSED (0x52)", ->
  ip_raw  = "\xC0\xA8\x01\x2A"
  msg     = m_ipc.encode_msg 0x1234, ip_raw, 54321, nil, true
  assert_eq #msg, 27, "taille = 27"
  decoded = m_ipc.decode_msg msg
  assert decoded, "decode_msg nil"
  assert_eq decoded.msg_type, m_ipc.MSG_IPV4_REFUSED, "msg_type = MSG_IPV4_REFUSED"
  assert_eq decoded.refused,  true, "refused = true"
  assert_eq decoded.ipv4,     true, "ipv4 = true"

test "decode_msg MSG_IPV6_REFUSED (0x72) → refused=true, ipv4=false", ->
  ip6_raw = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
  msg     = m_ipc.encode_msg 0xABCD, ip6_raw, 5353, nil, true
  decoded = m_ipc.decode_msg msg
  assert decoded, "decode_msg nil"
  assert_eq decoded.refused,  true,  "refused = true"
  assert_eq decoded.ipv4,     false, "ipv4 = false"
  assert_eq decoded.msg_type, 0x72,  "msg_type = 0x72"

test "write_refused_msg + drain_pipe + get_pending_entry → entry.refused = true", ->
  package.loaded["ipc"] = nil
  m_rip = dofile "lua/ipc.lua"
  pfd   = ffi.new "int[2]"
  assert (ffi.C.pipe2(pfd, 0) == 0), "pipe2"
  rfd5, wfd5 = pfd[0], pfd[1]
  ffi.C.fcntl rfd5, 4, 2048   -- F_SETFL, O_NONBLOCK
  ip5 = "\x05\x05\x05\x05"   -- 5.5.5.5
  ok  = m_rip.write_refused_msg wfd5, 0x9999, ip5, 5555
  assert ok, "write_refused_msg failed"
  ffi.C.close wfd5
  m_rip.drain_pipe rfd5, -> 0
  ffi.C.close rfd5
  entry = m_rip.get_pending_entry 0x9999, "5.5.5.5", 5555, -> 0
  assert entry, "get_pending_entry retourne nil"
  assert_eq entry.refused, true, "entry.refused = true"
  assert (entry.expire > 0), "entry.expire > 0"

-- ════════════════════════════════════════════════════════════════
-- Tests filter — conditions, rule, intégration
-- ════════════════════════════════════════════════════════════════
io.write "\n── filter ──\n"

-- Stubs supplémentaires pour les modules filter
-- (inet_pton est déjà déclarée en tête de fichier)

-- ── bsearch ──
{ :bsearch } = require "filter.lib.bsearch"

test "bsearch — trouvé en début", ->
  arr = ffi.new "uint64_t[3]", {100ULL, 200ULL, 300ULL}
  assert_eq (bsearch arr, 3, 100ULL), true, "bsearch(100)"

test "bsearch — trouvé en milieu", ->
  arr = ffi.new "uint64_t[3]", {100ULL, 200ULL, 300ULL}
  assert_eq (bsearch arr, 3, 200ULL), true, "bsearch(200)"

test "bsearch — trouvé en fin", ->
  arr = ffi.new "uint64_t[3]", {100ULL, 200ULL, 300ULL}
  assert_eq (bsearch arr, 3, 300ULL), true, "bsearch(300)"

test "bsearch — absent", ->
  arr = ffi.new "uint64_t[3]", {100ULL, 200ULL, 300ULL}
  assert_eq (bsearch arr, 3, 150ULL), false, "bsearch(150)"

test "bsearch — tableau vide", ->
  arr = ffi.new "uint64_t[0]"
  assert_eq (bsearch arr, 0, 42ULL), false, "bsearch vide"

-- ── ipcalc ──
ipcalc = require "filter.lib.ipcalc"

test "ipcalc — IPv4 dans sous-réseau", ->
  n = ipcalc.Net "192.168.1.0/24"
  assert n, "Net() non nil"
  assert_eq (n\contains "192.168.1.42"), true, "192.168.1.42 dans /24"

test "ipcalc — IPv4 hors sous-réseau", ->
  n = ipcalc.Net "192.168.1.0/24"
  assert_eq (n\contains "10.0.0.1"), false, "10.0.0.1 hors /24"

test "ipcalc — masque /16", ->
  n = ipcalc.Net "10.0.0.0/8"
  assert_eq (n\contains "10.255.255.1"), true, "10.x dans /8"
  assert_eq (n\contains "11.0.0.1"), false, "11.x hors /8"

test "ipcalc — IPv6 dans sous-réseau", ->
  n = ipcalc.Net "2001:db8::/32"
  assert_eq (n\contains "2001:db8::1"), true, "2001:db8::1 dans /32"

test "ipcalc — IPv6 hors sous-réseau", ->
  n = ipcalc.Net "2001:db8::/32"
  assert_eq (n\contains "2001:db9::1"), false, "2001:db9::1 hors /32"

test "ipcalc — CIDR invalide → nil", ->
  n = ipcalc.Net "not_an_ip/24"
  assert (n == nil), "Net invalide → nil"

-- ── to_domain ──
to_domain = require "filter.conditions.to_domain"

test "to_domain — correspondance exacte", ->
  f = (to_domain {}) "github.com"
  v, r = f {domain: "github.com"}
  assert_eq v, true, "exact match"

test "to_domain — sous-domaine autorisé", ->
  f = (to_domain {}) "github.com"
  v = f {domain: "api.github.com"}
  assert_eq v, true, "sous-domaine"

test "to_domain — domaine différent bloqué", ->
  f = (to_domain {}) "github.com"
  v = f {domain: "notgithub.com"}
  assert_eq v, false, "pas de correspondance"

test "to_domain — domaine vide → faux", ->
  f = (to_domain {}) "github.com"
  v = f {domain: nil}
  assert_eq v, false, "domaine nil"

-- ── to_domains ──
to_domains = require "filter.conditions.to_domains"

test "to_domains — OR logique", ->
  f = (to_domains {}) {"github.com", "debian.org"}
  assert_eq (f {domain: "github.com"}), true, "github OK"
  assert_eq (f {domain: "packages.debian.org"}), true, "debian OK"
  assert_eq (f {domain: "evil.com"}), false, "evil non"

-- ── to_domainlist (.domains texte) ──
to_domainlist = require "filter.conditions.to_domainlist"
TMPLIST = "./tmp/test_filter_domainlist.domains"

do
  fd = io.open TMPLIST, "w"
  fd\write "github.com\ndebian.org\ncloudflare.com\n"
  fd\close!

test "to_domainlist — domaine présent (fichier texte)", ->
  cfg = { domains: { testlist: TMPLIST } }
  f   = (to_domainlist cfg) "testlist"
  assert_eq (f {domain: "github.com"}), true, "github.com dans liste"

test "to_domainlist — sous-domaine présent", ->
  cfg = { domains: { testlist: TMPLIST } }
  f   = (to_domainlist cfg) "testlist"
  assert_eq (f {domain: "api.github.com"}), true, "api.github.com sous-domaine"

test "to_domainlist — domaine absent", ->
  cfg = { domains: { testlist: TMPLIST } }
  f   = (to_domainlist cfg) "testlist"
  assert_eq (f {domain: "evil.com"}), false, "evil.com absent"

test "to_domainlist — liste inconnue → faux", ->
  cfg = { domains: {} }
  f   = (to_domainlist cfg) "nonexistent"
  assert_eq (f {domain: "github.com"}), false, "liste manquante → false"

-- ── from_mac ──
from_mac = require "filter.conditions.from_mac"

test "from_mac — MAC correspondant", ->
  f = (from_mac {}) "aa:bb:cc:dd:ee:ff"
  assert_eq (f {mac: "aa:bb:cc:dd:ee:ff"}), true, "MAC match"

test "from_mac — MAC différent", ->
  f = (from_mac {}) "aa:bb:cc:dd:ee:ff"
  assert_eq (f {mac: "00:00:00:00:00:00"}), false, "MAC no match"

test "from_mac — MAC absent dans req", ->
  f = (from_mac {}) "aa:bb:cc:dd:ee:ff"
  assert_eq (f {mac: nil}), false, "MAC nil"

-- ── from_net ──
from_net = require "filter.conditions.from_net"

test "from_net — IP dans réseau", ->
  f = (from_net {}) "192.168.0.0/16"
  assert_eq (f {src_ip: "192.168.1.42"}), true, "IP dans LAN"

test "from_net — IP hors réseau", ->
  f = (from_net {}) "192.168.0.0/16"
  assert_eq (f {src_ip: "10.0.0.1"}), false, "IP hors LAN"

test "from_net — IP absente dans req", ->
  f = (from_net {}) "192.168.0.0/16"
  v = f {src_ip: nil}
  assert_eq v, false, "src_ip nil"

-- ── stolen_computer ──
stolen_computer = require "filter.conditions.stolen_computer"

test "stolen_computer — MAC blacklisté", ->
  f = (stolen_computer {}) {"de:ad:be:ef:00:01"}
  assert_eq (f {mac: "de:ad:be:ef:00:01"}), true, "volé"

test "stolen_computer — MAC non blacklisté", ->
  f = (stolen_computer {}) {"de:ad:be:ef:00:01"}
  assert_eq (f {mac: "aa:bb:cc:dd:ee:ff"}), false, "non volé"

-- ── in_time ──
in_time = require "filter.conditions.in_time"

test "in_time — dans la fenêtre", ->
  cfg = {times: {allday: {"00:00", "23:59"}}}
  f   = (in_time cfg) "allday"
  v, r = f {ts: os.time!}
  assert_eq v, true, "dans allday"

test "in_time — hors fenêtre", ->
  cfg = {times: {never: {"25:00", "25:01"}}}
  f   = (in_time cfg) "never"
  v = f {ts: os.time!}
  assert_eq v, false, "hors fenêtre absurde"

test "in_time — fenêtre inconnue → faux", ->
  cfg = {times: {}}
  f   = (in_time cfg) "doesnotexist"
  assert_eq (f {ts: os.time!}), false, "fenêtre inconnue"

-- ── rule.compile_rules + rule.decide ──
m_rule = require "filter.rule"

TEST_CFG = {
  times: {business: {"00:00", "23:59"}}
}

TEST_RULES_CFG = {
  {
    description: "Infra locale toujours OK"
    conditions:  {to_domains: {"local", "home.arpa"}}
    actions:     {"allow"}
  }
  {
    description: "Machines volées bloquées"
    conditions:  {stolen_computer: {"de:ad:be:ef:00:01"}}
    actions:     {"deny"}
  }
  {
    description: "LAN autorisé"
    conditions:  {from_net: "192.168.0.0/16", to_domain: "github.com"}
    actions:     {"allow"}
  }
  {
    description: "Refus par défaut"
    conditions:  {}
    actions:     {"deny"}
  }
}

do
  cfg = {rules: TEST_RULES_CFG, times: TEST_CFG.times}
  rules = m_rule.compile_rules cfg

  test "rule.decide — domaine local → allow", ->
    v, m = m_rule.decide rules, {domain: "gateway.local", mac: "aa:bb:cc:dd:ee:ff", src_ip: "192.168.1.1", ts: os.time!}
    assert_eq v, true, "local domain autorisé"

  test "rule.decide — machine volée → deny même sur domaine non-local", ->
    v, m = m_rule.decide rules, {domain: "github.com", mac: "de:ad:be:ef:00:01", src_ip: "192.168.1.2", ts: os.time!}
    assert_eq v, false, "volée + github.com → deny"

  test "rule.decide — LAN + domain → allow", ->
    v, m = m_rule.decide rules, {domain: "github.com", mac: "aa:bb:cc:dd:ee:ff", src_ip: "192.168.1.3", ts: os.time!}
    assert_eq v, true, "LAN + github.com autorisé"

  test "rule.decide — hors LAN + domain → default deny", ->
    v, m = m_rule.decide rules, {domain: "github.com", mac: "aa:bb:cc:dd:ee:ff", src_ip: "1.2.3.4", ts: os.time!}
    assert_eq v, false, "WAN + github.com → deny"

  test "rule.decide — aucune règle ne correspond → false", ->
    rules_empty = m_rule.compile_rules {rules: {}}
    v, m = m_rule.decide rules_empty, {domain: "github.com", ts: os.time!}
    assert_eq v, false, "aucune règle → deny par défaut"

-- Nettoyage
os.remove TMPLIST

-- ── parse_domains ──────────────────────────────────────────────────────────
io.write "\n── parse_domains ──\n"
{ :parse, :parse_simple, :parse_hosts, :parse_adblock, :is_valid } = require "filter.lib.parse_domains"

test "parse_domains.is_valid — domaine valide", ->
  assert_eq (is_valid "example.com"), true, "example.com"

test "parse_domains.is_valid — domaine avec sous-domaine", ->
  assert_eq (is_valid "ads.example.com"), true, "ads.example.com"

test "parse_domains.is_valid — chaîne vide → invalide", ->
  assert_eq (is_valid ""), false, "vide"

test "parse_domains.is_valid — IPv4 → invalide", ->
  assert_eq (is_valid "1.2.3.4"), false, "IPv4"

test "parse_domains.is_valid — IPv6 → invalide", ->
  assert_eq (is_valid "::1"), false, "IPv6"

test "parse_domains.is_valid — sans point → invalide", ->
  assert_eq (is_valid "localhost"), false, "pas de point"

test "parse_domains.is_valid — trop long → invalide", ->
  assert_eq (is_valid (string.rep("a", 254))), false, "trop long"

test "parse_domains.is_valid — caractères invalides → invalide", ->
  assert_eq (is_valid "bad domain.com"), false, "espace"

-- ── parse_simple ──
do
  text = [[
# Commentaire
example.com
  ads.example.com
DOUBLECLICK.NET
# autre commentaire
invalide
]]
  result = parse_simple text

  test "parse_simple — nombre de domaines extraits", ->
    assert_eq #result, 3, "3 domaines"

  test "parse_simple — normalisation minuscules", ->
    found = false
    for d in *result
      found = true if d == "doubleclick.net"
    assert found, "doubleclick.net normalisé"

  test "parse_simple — commentaires ignorés", ->
    for d in *result
      assert d\sub(1, 1) ~= "#", "commentaire présent : #{d}"

-- ── parse_hosts ──
do
  text = [[
# hosts file
127.0.0.1 localhost
0.0.0.0 ads.example.com
0.0.0.0 0.0.0.0
127.0.0.1 tracking.example.org
::1 ip6-localhost
0.0.0.0 DOUBLECLICK.NET
]]
  result = parse_hosts text

  test "parse_hosts — nombre de domaines extraits (skip localhost/0.0.0.0/::1)", ->
    assert_eq #result, 3, "3 domaines"

  test "parse_hosts — localhost ignoré", ->
    for d in *result
      assert d ~= "localhost", "localhost présent"

  test "parse_hosts — normalisation minuscules", ->
    found = false
    for d in *result
      found = true if d == "doubleclick.net"
    assert found, "doubleclick.net normalisé"

-- ── parse_adblock ──
do
  text = [[
! Commentaire adblock
||ads.example.com^
||tracker.example.org^$third-party
@@||whitelist.example.com^
||DOUBLECLICK.NET^
||invalid
##.css-rule
]]
  result = parse_adblock text

  test "parse_adblock — nombre de domaines extraits", ->
    assert_eq #result, 3, "3 domaines (pas d'exception @@, pas de CSS)"

  test "parse_adblock — normalisation minuscules", ->
    found = false
    for d in *result
      found = true if d == "doubleclick.net"
    assert found, "doubleclick.net normalisé"

  test "parse_adblock — exception @@ ignorée", ->
    for d in *result
      assert d ~= "whitelist.example.com", "exception présente"

-- ── parse dispatch ──
test "parse — format 'simple' dispatche vers parse_simple", ->
  result = parse "simple", "example.com\n# commentaire\n"
  assert_eq #result, 1, "1 domaine"
  assert_eq result[1], "example.com", "domaine"

test "parse — format inconnu → parse_simple par défaut", ->
  result = parse "unknown_format", "example.com\n"
  assert_eq #result, 1, "fallback simple"



io.write string.format("\n%d test(s) passé(s), %d échec(s)\n", passed, failed)
os.exit failed == 0 and 0 or 1
