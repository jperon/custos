-- tests/unit/parse/ndpi_spec.moon
-- Spec Busted pour lua/parse/ndpi.lua
-- Runner : busted --lua=luajit --loaders=lua
-- Les stubs de base (ffi_defs, config, log, parse/ethernet) sont injectés
-- par tests/helpers/busted_setup.lua avant le chargement de ce fichier.

bit = require "bit"
ffi = require "ffi"

-- ── Stubs nDPI injectés avant dofile ─────────────────────────────────────────
-- Doit précéder le premier dofile "lua/parse/ndpi.lua" pour que le module
-- choisisse le bon backend sans tenter de charger libndpi.so.
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

-- Chargement du module sous test
m_ndpi               = dofile "lua/parse/ndpi.lua"
parse_packet         = m_ndpi.parse_packet
patch_and_checksum   = m_ndpi.patch_and_checksum
extract_dns_payload  = m_ndpi.extract_dns_payload
patch_ttl_in_dns     = m_ndpi.patch_ttl_in_dns
replace_dns_payload  = m_ndpi.replace_dns_payload

-- ── Helpers de construction de paquets ───────────────────────────────────────

-- Construit un message DNS minimal : header (12 B) + 1 question.
-- qname_encoded : labels DNS encodés ex. "\3www\6github\3com\0"
-- qtype         : uint16 (défaut A=1)
-- is_response   : bool
-- txid          : uint16 (défaut 0x1234)
make_dns = (qname_encoded, qtype, is_response, txid) ->
  txid  = txid or 0x1234
  qtype = qtype or 1
  flags_hi = is_response and 0x81 or 0x01
  flags_lo = 0x00
  hdr = string.char(
    bit.rshift(bit.band(txid, 0xFF00), 8), bit.band(txid, 0xFF),
    flags_hi, flags_lo,
    0, 1,
    0, 0,
    0, 0,
    0, 0
  )
  qsection = qname_encoded .. string.char(0, qtype, 0, 1)
  hdr .. qsection

-- Paquet IPv4 / UDP / DNS (20 B IP + 8 B UDP + payload)
make_ipv4_udp_dns = (src_ip, dst_ip, src_port, dst_port, dns_payload) ->
  total_len = 20 + 8 + #dns_payload
  ihl_ver = 0x45
  ip4bytes = (s) ->
    a, b, c, d = s\match "(%d+)%.(%d+)%.(%d+)%.(%d+)"
    string.char tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  ip = string.char(
    ihl_ver, 0,
    bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF),
    0, 1,
    0, 0,
    64,
    17,
    0, 0
  )
  ip = ip .. ip4bytes(src_ip) .. ip4bytes(dst_ip)
  udp_len = 8 + #dns_payload
  udp = string.char(
    bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF),
    bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF),
    bit.rshift(bit.band(udp_len,  0xFF00), 8), bit.band(udp_len,  0xFF),
    0, 0
  )
  ip .. udp .. dns_payload

-- Paquet IPv4 / TCP / DNS (20 B IP + 20 B TCP + 2 B length-prefix + payload)
make_ipv4_tcp_dns = (src_ip, dst_ip, src_port, dst_port, dns_payload) ->
  dns_len    = #dns_payload
  pfx = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF))
  tcp_payload = pfx .. dns_payload
  total_len  = 20 + 20 + #tcp_payload
  ip4bytes = (s) ->
    a, b, c, d = s\match "(%d+)%.(%d+)%.(%d+)%.(%d+)"
    string.char tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  ip = string.char(
    0x45, 0,
    bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF),
    0, 1, 0, 0, 64,
    6,
    0, 0
  )
  ip = ip .. ip4bytes(src_ip) .. ip4bytes(dst_ip)
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

-- Paquet IPv6 / UDP / DNS (40 B IPv6 fixe + 8 B UDP + payload)
-- src_ip6 / dst_ip6 : strings de 16 octets bruts
make_ipv6_udp_dns = (src_ip6, dst_ip6, src_port, dst_port, dns_payload) ->
  udp_len = 8 + #dns_payload
  pay_len = udp_len
  ip6 = string.char(
    0x60, 0, 0, 0,
    bit.rshift(bit.band(pay_len, 0xFF00), 8), bit.band(pay_len, 0xFF),
    17,
    64
  ) .. src_ip6 .. dst_ip6
  udp = string.char(
    bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF),
    bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF),
    bit.rshift(bit.band(udp_len,  0xFF00), 8), bit.band(udp_len,  0xFF),
    0, 0
  )
  ip6 .. udp .. dns_payload

-- Paquet IPv6 + extension headers + UDP / DNS
-- first_nh : NH dans l'en-tête IPv6 fixe (type du premier ext hdr)
-- ext_raw  : octets bruts des ext hdrs chaînés ; le NH du dernier doit être 17
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

-- Helper TCP brut (séquence TCP fournie explicitement, sans ajouter de prefix)
make_tcp_raw = (src_ip, dst_ip, src_port, dst_port, tcp_seq, tcp_payload) ->
  total_len = 20 + 20 + #tcp_payload
  ip4b = (s) ->
    a, b, c, d = s\match "(%d+)%.(%d+)%.(%d+)%.(%d+)"
    string.char tonumber(a), tonumber(b), tonumber(c), tonumber(d)
  ip = string.char(
    0x45, 0,
    bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF),
    0, 1, 0, 0, 64, 6, 0, 0
  ) .. ip4b(src_ip) .. ip4b(dst_ip)
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

-- ═════════════════════════════════════════════════════════════════════════════
describe "parse/ndpi", ->

  -- ── parse_packet ───────────────────────────────────────────────────────────
  describe "parse_packet", ->

    it "UDP DNS minimal", ->
      dns = make_dns "\3www\6github\3com\0", 1, false
      raw = make_ipv4_udp_dns "192.168.1.42", "8.8.8.8", 54321, 53, dns
      pkt = parse_packet raw
      assert.is_not_nil pkt, "parse_packet ne doit pas retourner nil"
      assert.equals "udp", pkt.l4.proto
      assert.equals 0x1234, pkt.dns.txid
      assert.equals "www.github.com", pkt.questions[1].qname

    it "TCP DNS minimal", ->
      dns = make_dns "\3www\6github\3com\0", 1, false
      raw = make_ipv4_tcp_dns "192.168.1.42", "8.8.8.8", 54321, 53, dns
      pkt = parse_packet raw
      assert.is_not_nil pkt, "parse_packet ne doit pas retourner nil"
      assert.equals "tcp", pkt.l4.proto
      assert.equals 0x1234, pkt.dns.txid
      assert.equals "www.github.com", pkt.questions[1].qname

    it "TCP DNS too short (no length prefix)", ->
      -- make_ipv4_tcp_dns ajoute 2 octets de prefix → on tronque de 1 pour
      -- simuler un segment TCP incomplet (payload < 14 B minimum).
      raw = make_ipv4_tcp_dns "192.168.1.42", "8.8.8.8", 54322, 53, ""
      raw = raw\sub 1, #raw - 1
      pkt = parse_packet raw
      assert.is_nil pkt, "doit retourner nil si payload TCP < 14 B"

    it "IPv6 + Hop-by-Hop (type 0) + UDP DNS", ->
      -- Hop-by-Hop 8 B : NH=17(UDP), HdrExtLen=0, 6 octets de padding
      hbh = string.char 17, 0, 0, 0, 0, 0, 0, 0
      dns = make_dns "\3www\6github\3com\0", 1, false
      src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
      dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
      raw  = make_ipv6_ext_udp_dns src6, dst6, 54321, 53, dns, 0, hbh
      pkt  = parse_packet raw
      assert.is_not_nil pkt, "parse_packet nil avec Hop-by-Hop"
      assert.equals 6,   pkt.ip.version
      -- ihl = 40 B IPv6 fixe + 8 B ext = 48
      assert.equals 48,  pkt.ip.ihl
      assert.equals "udp", pkt.l4.proto
      assert.equals 0x1234, pkt.dns.txid
      assert.equals "www.github.com", pkt.questions[1].qname

    it "IPv6 + Routing (type 43) + UDP DNS", ->
      -- Routing header 8 B : NH=17, HdrExtLen=0, 6 octets
      rh  = string.char 17, 0, 0, 0, 0, 0, 0, 0
      dns = make_dns "\3www\6github\3com\0", 1, false
      src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
      dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
      raw  = make_ipv6_ext_udp_dns src6, dst6, 54321, 53, dns, 43, rh
      pkt  = parse_packet raw
      assert.is_not_nil pkt, "parse_packet nil avec Routing header"
      assert.equals 48,    pkt.ip.ihl
      assert.equals "udp", pkt.l4.proto
      assert.equals "www.github.com", pkt.questions[1].qname

    it "IPv6 + Fragment (type 44) + UDP DNS", ->
      -- Fragment header 8 B : NH=17, Reserved=0, FragOff=0, M=0, ID=1
      fh  = string.char 17, 0, 0, 0, 0, 0, 0, 1
      dns = make_dns "\3www\6github\3com\0", 1, false
      src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
      dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
      raw  = make_ipv6_ext_udp_dns src6, dst6, 54321, 53, dns, 44, fh
      pkt  = parse_packet raw
      assert.is_not_nil pkt, "parse_packet nil avec Fragment header"
      assert.equals 48,    pkt.ip.ihl
      assert.equals "udp", pkt.l4.proto
      assert.equals "www.github.com", pkt.questions[1].qname

    it "IPv6 + Hop-by-Hop + Routing (chained) + UDP DNS", ->
      -- Hop-by-Hop (NH=43) → Routing (NH=17) → UDP
      hbh = string.char 43, 0, 0, 0, 0, 0, 0, 0   -- NH pointe vers Routing
      rh  = string.char 17, 0, 0, 0, 0, 0, 0, 0   -- NH pointe vers UDP
      dns = make_dns "\3www\6github\3com\0", 1, false
      src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
      dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"
      raw  = make_ipv6_ext_udp_dns src6, dst6, 54321, 53, dns, 0, hbh .. rh
      pkt  = parse_packet raw
      assert.is_not_nil pkt, "parse_packet nil avec ext headers chaînés"
      -- ihl = 40 + 8 (HBH) + 8 (Routing) = 56
      assert.equals 56,    pkt.ip.ihl
      assert.equals "udp", pkt.l4.proto
      assert.equals "www.github.com", pkt.questions[1].qname

  -- ── patch_and_checksum ─────────────────────────────────────────────────────
  describe "patch_and_checksum", ->

    it "TCP response", ->
      -- Réponse DNS : 1 question + 1 RR A, TTL=300 (0x0000012C)
      qname_enc = "\6github\3com\0"   -- 12 octets
      txid = 0x5678
      -- header : QR=1 RD=1 RA=1, qdcount=1, ancount=1
      hdr      = string.char(0x56, 0x78, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
      question = qname_enc .. string.char(0, 1, 0, 1)   -- 16 octets
      -- RR : ptr(2) + TYPE A(2) + CLASS IN(2) + TTL=300(4) + rdlen=4(2) + rdata(4)
      rr       = "\xC0\x0C" ..
        string.char(0, 1, 0, 1) ..
        string.char(0, 0, 1, 0x2C) ..
        string.char(0, 4) ..
        string.char(1, 2, 3, 4)
      dns_payload = hdr .. question .. rr

      raw = make_ipv4_tcp_dns "192.168.1.42", "8.8.8.8", 54323, 53, dns_payload
      pkt = parse_packet raw
      assert.is_not_nil pkt, "parse_packet retourne nil"

      answers = m_ndpi.parse_answers raw, pkt
      patched = patch_and_checksum raw, pkt, answers, 60
      assert.is_not_nil patched, "patch_and_checksum retourne nil"

      -- Offset 0-based du TTL LSB dans le paquet patché :
      -- IP(20) + TCP(20) + LenPfx(2) + DNS_hdr(12) + question(16) + RR_ptr+type+class(6) + TTL[3]
      -- question = "\6github\3com\0"(12) + qtype(2) + qclass(2) = 16 B
      -- RR prefix = ptr(2) + type(2) + class(2) = 6 B  → offset TTL LSB = 79
      ttl_offset = 20 + 20 + 2 + 12 + 16 + 6 + 3   -- = 79 (0-based)
      assert.equals 60, patched\byte(ttl_offset + 1), "TTL patché à 60"

    it "TCP 2-segment reassembly patches TTL", ->
      -- DNS réponse : 1 A RR, TTL=300.  Port 54324 pour isoler tcp_buffers.
      qname_enc = "\6github\3com\0"   -- 12 octets
      hdr       = string.char(0x9A, 0xBC, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
      question  = qname_enc .. string.char(0, 1, 0, 1)
      rr        = "\xC0\x0C" ..
        string.char(0, 1, 0, 1) ..
        string.char(0, 0, 1, 0x2C) ..
        string.char(0, 4) ..
        string.char(5, 6, 7, 8)
      dns_payload = hdr .. question .. rr
      dns_len = #dns_payload

      src_ip, dst_ip, src_port, dst_port = "192.168.1.42", "8.8.8.8", 54324, 53
      init_seq = 0x00ABCDEF

      -- Segment 1 : seulement le prefix 2 octets de longueur DNS
      prefix = string.char(
        bit.rshift(bit.band(dns_len, 0xFF00), 8),
        bit.band(dns_len, 0xFF)
      )
      raw1 = make_tcp_raw src_ip, dst_ip, src_port, dst_port, init_seq, prefix
      pkt1, status1 = parse_packet raw1
      assert.is_nil pkt1,              "seg1 doit retourner nil (incomplet)"
      assert.equals "buffering", status1, "seg1 doit signaler buffering"

      -- Segment 2 : payload DNS (sans prefix)
      raw2 = make_tcp_raw src_ip, dst_ip, src_port, dst_port, init_seq + 2, dns_payload
      pkt2 = (parse_packet raw2)
      assert.is_not_nil pkt2, "seg2 doit compléter le message DNS"
      assert.equals "tcp",    pkt2.l4.proto
      assert.equals 0x9ABC,   pkt2.dns.txid
      assert.equals false,    pkt2.tcp_single_segment
      assert.is_not_nil pkt2.tcp_init_seq, "tcp_init_seq doit être défini"
      assert.equals init_seq, pkt2.tcp_init_seq

      answers2 = m_ndpi.parse_answers raw2, pkt2
      assert.equals 1, #answers2, "1 réponse attendue"

      patched2 = patch_and_checksum raw2, pkt2, answers2, 60

      -- Longueur du paquet coalesced = IP(20) + TCP(20) + prefix(2) + dns_len
      expected_len = 20 + 20 + 2 + dns_len
      assert.equals expected_len, #patched2, "taille du paquet coalesced"

      -- TTL LSB à l'offset 0-based : base(42) + hdr(12) + question(16) + RR_ptr+type+class(6) + TTL[3]
      ttl_off2 = 20 + 20 + 2 + 12 + 16 + 6 + 3   -- = 79 (0-based)
      assert.equals 60, patched2\byte(ttl_off2 + 1), "TTL patché à 60 dans paquet coalesced"

      -- Le champ seq TCP doit avoir été restauré à init_seq
      seq_b0 = patched2\byte(20 + 4 + 1)
      seq_b1 = patched2\byte(20 + 4 + 2)
      seq_b2 = patched2\byte(20 + 4 + 3)
      seq_b3 = patched2\byte(20 + 4 + 4)
      got_seq = bit.bor(
        bit.lshift(seq_b0, 24),
        bit.lshift(seq_b1, 16),
        bit.lshift(seq_b2,  8),
        seq_b3
      )
      assert.equals init_seq, got_seq, "champ seq TCP restauré à init_seq"

    it "TCP 2-segment CNAME+A patches all TTLs", ->
      -- DNS réponse : 2 RR (CNAME + A), TTLs=300.  Port 54325.
      qname_enc = "\6github\3com\0"   -- 12 octets (offset DNS = 12)
      hdr       = string.char(0xBB, 0xCC, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0)
      question  = qname_enc .. string.char(0, 1, 0, 1)   -- 16 octets

      -- RR1 CNAME à l'offset DNS 28 :
      --   ptr(2)+TYPE5(2)+IN(2)+TTL300(4)+rdlen16(2)+cname_target(16) = 28 B
      cname_target = "\3www\6github\3com\0"   -- 16 octets
      rr1 = "\xC0\x0C" ..
        string.char(0, 5, 0, 1) ..
        string.char(0, 0, 1, 0x2C) ..    -- TTL=300 ; ttl_offset=34 (0-based)
        string.char(0, 16) ..
        cname_target

      -- RR2 A à l'offset DNS 56 :
      --   ptr(2)+TYPE1(2)+IN(2)+TTL300(4)+rdlen4(2)+ip(4) = 16 B
      rr2 = "\xC0\x0C" ..
        string.char(0, 1, 0, 1) ..
        string.char(0, 0, 1, 0x2C) ..    -- TTL=300 ; ttl_offset=62 (0-based)
        string.char(0, 4) ..
        string.char(1, 2, 3, 4)

      dns_payload = hdr .. question .. rr1 .. rr2
      dns_len = #dns_payload
      assert.equals 72, dns_len, "dns_payload doit faire 72 B"

      src_ip, dst_ip, src_port, dst_port = "192.168.1.42", "8.8.8.8", 54325, 53
      init_seq2 = 0x00112233

      prefix = string.char(
        bit.rshift(bit.band(dns_len, 0xFF00), 8),
        bit.band(dns_len, 0xFF)
      )
      raw1 = make_tcp_raw src_ip, dst_ip, src_port, dst_port, init_seq2, prefix
      p1, s1 = parse_packet raw1
      assert.is_nil p1,              "seg1 nil"
      assert.equals "buffering", s1, "seg1 buffering"

      raw2 = make_tcp_raw src_ip, dst_ip, src_port, dst_port, init_seq2 + 2, dns_payload
      pkt3 = (parse_packet raw2)
      assert.is_not_nil pkt3, "seg2 doit compléter le message DNS"
      assert.equals 0xBBCC, pkt3.dns.txid
      assert.equals false,  pkt3.tcp_single_segment

      ans3 = m_ndpi.parse_answers raw2, pkt3
      assert.equals 2,   #ans3,       "2 réponses (CNAME + A)"
      assert.equals 300, ans3[1].ttl, "RR1 TTL original = 300"
      assert.equals 300, ans3[2].ttl, "RR2 TTL original = 300"

      patched3 = patch_and_checksum raw2, pkt3, ans3, 42

      -- base = IP(20) + TCP(20) + prefix(2) = 42 octets
      base = 42
      -- RR1 ttl_offset=34 → TTL LSB = base + 34 + 3 = 79 (0-based) → byte(80)
      assert.equals 42, patched3\byte(base + 34 + 3 + 1), "RR1 (CNAME) TTL patché à 42"
      -- RR2 ttl_offset=62 → TTL LSB = base + 62 + 3 = 107 (0-based) → byte(108)
      assert.equals 42, patched3\byte(base + 62 + 3 + 1), "RR2 (A) TTL patché à 42"
      -- Octets de poids fort = 0 (42 < 256)
      assert.equals 0, patched3\byte(base + 34 + 0 + 1), "RR1 TTL byte0 = 0"
      assert.equals 0, patched3\byte(base + 34 + 1 + 1), "RR1 TTL byte1 = 0"
      assert.equals 0, patched3\byte(base + 34 + 2 + 1), "RR1 TTL byte2 = 0"
      assert.equals 0, patched3\byte(base + 62 + 0 + 1), "RR2 TTL byte0 = 0"
      assert.equals 0, patched3\byte(base + 62 + 1 + 1), "RR2 TTL byte1 = 0"
      assert.equals 0, patched3\byte(base + 62 + 2 + 1), "RR2 TTL byte2 = 0"

  -- ── helpers purs ndpi ──────────────────────────────────────────────────────
  describe "helpers ndpi", ->

    -- Second dofile isolé avec ses propres stubs (les stubs sont déjà dans
    -- package.loaded depuis le début du fichier ; on récupère le même module
    -- ou on le recharge proprement).
    -- NOTE : m_ndpi est déjà chargé en tête de fichier ; les helpers sont
    -- extraits directement depuis ce module.

    it "extract_dns_payload — UDP : retourne la sous-chaîne DNS", ->
      dns = make_dns "\x06github\x03com\x00", 1, false, 0xABCD
      raw = make_ipv4_udp_dns "192.168.1.2", "8.8.8.8", 54321, 53, dns
      pkt = {
        ip: {version: 4, ihl: 20}
        l4: {proto: "udp", off: 28, payload_len: #dns}
      }
      result = extract_dns_payload raw, pkt
      assert.equals dns, result, "payload DNS extrait correctement"

    it "extract_dns_payload — TCP : retourne pkt.tcp_dns_raw", ->
      dns = make_dns "\x03foo\x03com\x00", 1, false, 0x4321
      pkt = {l4: {proto: "tcp"}, tcp_dns_raw: dns}
      result = extract_dns_payload "ignored", pkt
      assert.equals dns, result, "retourne pkt.tcp_dns_raw"

    it "patch_ttl_in_dns — réécrit TTL à l'offset 0-based correct, class intact", ->
      -- DNS : header(12 B) + question(16 B) + RR answer
      qname_enc = "\x06github\x03com\x00"   -- 12 octets
      hdr       = string.char(0x56, 0x78, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
      question  = qname_enc .. string.char(0, 1, 0, 1)   -- 16 octets
      -- RR : ptr(2) + TYPE A(2) + CLASS IN(2) + TTL=300(4) + rdlen=4(2) + rdata(4)
      rr = "\xC0\x0C" ..
        string.char(0, 1, 0, 1) ..
        string.char(0, 0, 1, 0x2C) ..
        string.char(0, 4) ..
        string.char(1, 2, 3, 4)
      dns_str = hdr .. question .. rr

      -- answers_off = 12 + 16 = 28
      -- decode_name à pos=28 : ptr 0xC00C → consumed=2, pos→30
      -- ttl_offset = 30 + 4 = 34 (0-based)
      ttl_off = 34
      result  = patch_ttl_in_dns dns_str, {{ttl_offset: ttl_off}}, 60

      assert.is_not_nil result, "patch_ttl_in_dns ne doit pas retourner nil"
      assert.equals #dns_str, #result, "longueur inchangée"

      -- CLASS IN = 0x0001 aux 0-based 32-33 (1-based 33-34)
      assert.equals 0x00, result\byte(33), "CLASS hi non corrompu"
      assert.equals 0x01, result\byte(34), "CLASS lo = IN (1) non corrompu"

      -- TTL = 60 aux 0-based 34-37 (1-based 35-38)
      assert.equals 0x00, result\byte(35), "TTL byte 0 = 0x00"
      assert.equals 0x00, result\byte(36), "TTL byte 1 = 0x00"
      assert.equals 0x00, result\byte(37), "TTL byte 2 = 0x00"
      assert.equals 60,   result\byte(38), "TTL byte 3 = 60"

    it "patch_ttl_in_dns — answers vide → payload inchangé", ->
      dns_str = make_dns "\x03foo\x03com\x00", 1, false, 0x1111
      result  = patch_ttl_in_dns dns_str, {}, 60
      assert.is_not_nil result, "retourne non-nil même sans answers"
      assert.equals dns_str, result, "payload inchangé si answers vide"

    it "replace_dns_payload — IPv4 UDP : longueurs IP et UDP mises à jour", ->
      dns_orig = make_dns "\x06github\x03com\x00", 1, false, 0xABCD
      raw      = make_ipv4_udp_dns "8.8.8.8", "192.168.1.42", 53, 54321, dns_orig
      pkt      = {
        ip: {version: 4, ihl: 20}
        l4: {proto: "udp", off: 28, payload_len: #dns_orig}
      }
      new_dns  = dns_orig .. "\x00\x00\x00\x00"   -- 4 octets supplémentaires
      result   = replace_dns_payload raw, pkt, new_dns

      assert.is_not_nil result, "replace_dns_payload ne doit pas retourner nil"

      expected_total = 20 + 8 + #new_dns
      assert.equals expected_total, #result, "longueur totale du paquet"

      -- IP total_len aux bytes 3-4 (1-based)
      ip_len = bit.bor(bit.lshift(result\byte(3), 8), result\byte(4))
      assert.equals expected_total, ip_len, "IP total_len mis à jour"

      -- UDP length aux bytes 25-26 (1-based : après IP 20 B, udp len à offset 4 dans UDP)
      udp_len_field = bit.bor(bit.lshift(result\byte(25), 8), result\byte(26))
      assert.equals 8 + #new_dns, udp_len_field, "UDP length mis à jour"

      -- Payload DNS aux bytes 29..28+#new_dns (1-based)
      assert.equals new_dns, result\sub(29, 28 + #new_dns), "payload DNS correct"

    it "replace_dns_payload — IPv4 TCP : longueur IP et DNS prefix mis à jour", ->
      dns_orig = make_dns "\x03foo\x03com\x00", 1, false, 0x2222
      raw      = make_ipv4_tcp_dns "8.8.8.8", "192.168.1.42", 53, 54321, dns_orig
      pkt      = {
        ip: {version: 4, ihl: 20}
        l4: {proto: "tcp"}
        tcp_init_seq: 0
      }
      new_dns = dns_orig .. "\xAB\xCD"   -- 2 octets supplémentaires
      result  = replace_dns_payload raw, pkt, new_dns

      assert.is_not_nil result, "replace_dns_payload TCP ne doit pas retourner nil"

      -- total = IP(20) + TCP(20) + prefix(2) + #new_dns
      expected_total = 20 + 20 + 2 + #new_dns
      assert.equals expected_total, #result, "longueur totale TCP"

      -- IP total_len aux bytes 3-4
      ip_len = bit.bor(bit.lshift(result\byte(3), 8), result\byte(4))
      assert.equals expected_total, ip_len, "IP total_len mis à jour"

      -- DNS length prefix aux bytes 41-42 (1-based : 20+20=40 octets d'en-têtes + 1)
      dns_prefix = bit.bor(bit.lshift(result\byte(41), 8), result\byte(42))
      assert.equals #new_dns, dns_prefix, "DNS length prefix (TCP) = longueur DNS"

      -- DNS payload aux bytes 43..42+#new_dns
      assert.equals new_dns, result\sub(43, 42 + #new_dns), "payload DNS TCP correct"

-- ═════════════════════════════════════════════════════════════════════════════
-- Couverture supplémentaire : branches non couvertes
-- ═════════════════════════════════════════════════════════════════════════════

-- ── ndpi_v5 backend ──────────────────────────────────────────────────────────
describe "parse/ndpi — ndpi_v5 backend", ->

  it "major=5 charge le backend ndpi_v5", ->
    -- Réinitialiser les modules pour forcer le rechargement
    package.loaded["parse.ndpi"] = nil
    package.loaded["ffi_ndpi"] = {
      ffi:      ffi
      ndpi_lib: {}
      major:    5
    }
    -- Les stubs v4/v5 sont déjà dans package.loaded depuis le début du fichier
    m5 = dofile "lua/parse/ndpi.lua"
    -- On vérifie que le module se charge sans erreur avec major=5
    assert.is_not_nil m5, "module ndpi chargé avec major=5"
    assert.is_not_nil m5.parse_packet, "parse_packet exporté"
    assert.is_not_nil m5.purge_flows, "purge_flows exporté"
    -- Restaurer le stub v4 pour le reste des tests
    package.loaded["parse.ndpi"] = nil
    package.loaded["ffi_ndpi"] = {
      ffi:      ffi
      ndpi_lib: {}
      major:    4
    }

-- ── QTYPE / RCODE constants ──────────────────────────────────────────────────
describe "parse/ndpi — constantes QTYPE et RCODE", ->

  it "QTYPE.ANY == 255", ->
    assert.equals 255, m_ndpi.QTYPE.ANY

  it "RCODE.REFUSED == 5", ->
    assert.equals 5, m_ndpi.RCODE.REFUSED

  it "QTYPE_NAME[255] == 'ANY'", ->
    assert.equals "ANY", m_ndpi.QTYPE_NAME[255]

-- ── purge_flows / purge_tcp_buffers ──────────────────────────────────────────
describe "parse/ndpi — purge_flows et purge_tcp_buffers", ->

  -- Module frais avec un ndpi_lib qui peut répondre à get_sizeof
  fresh_ndpi_with_flow = ->
    package.loaded["parse.ndpi"] = nil
    package.loaded["ffi_ndpi"] = {
      ffi:      ffi
      ndpi_lib: {
        ndpi_detection_get_sizeof_ndpi_flow_struct: -> 64
      }
      major:    4
    }
    -- ndpi_flow_struct doit être déclaré pour ffi.cast
    pcall ffi.cdef, "typedef struct ndpi_flow_struct ndpi_flow_struct;"
    package.loaded["parse.ndpi_v4"] = {
      init:    -> nil
      detect:  -> 0, 0
      cleanup: -> nil
    }
    m = dofile "lua/parse/ndpi.lua"
    -- Restaurer le stub original
    package.loaded["parse.ndpi"] = nil
    package.loaded["ffi_ndpi"] = { ffi: ffi, ndpi_lib: {}, major: 4 }
    m

  it "purge_flows(0) s'exécute sans erreur (table vide)", ->
    m = fresh_ndpi_with_flow!
    ok, err = pcall m.purge_flows, 0
    assert.is_true ok, "purge_flows ne doit pas lever d'erreur: " .. tostring(err)

  it "purge_flows(300) avec défaut max_age", ->
    m = fresh_ndpi_with_flow!
    ok, err = pcall m.purge_flows
    assert.is_true ok, "purge_flows() sans argument ne doit pas lever d'erreur: " .. tostring(err)

  it "purge_tcp_buffers(0) s'exécute sans erreur", ->
    m = fresh_ndpi_with_flow!
    ok, err = pcall m.purge_tcp_buffers, 0
    assert.is_true ok, "purge_tcp_buffers ne doit pas lever d'erreur: " .. tostring(err)

  it "purge_tcp_buffers() avec défaut max_age", ->
    m = fresh_ndpi_with_flow!
    ok, err = pcall m.purge_tcp_buffers
    assert.is_true ok, "purge_tcp_buffers() sans argument: " .. tostring(err)

  it "purge_flows expire un flow créé dans le passé", ->
    m = fresh_ndpi_with_flow!
    -- Créer un flow via parse_packet (TCP, port unique pour isoler)
    dns = make_dns "\3foo\3bar\0", 1, false, 0xABCD
    raw = make_ipv4_tcp_dns "192.168.5.1", "8.8.8.8", 59990, 53, dns
    parse_packet raw  -- peuple tcp_buffers et potentiellement flow_cache
    -- purge avec max_age=0 → tous les flows expirés (timestamp passé)
    ok, err = pcall m.purge_flows, 0
    assert.is_true ok, "purge_flows(0) apres flow: " .. tostring(err)

  it "purge_tcp_buffers expire un buffer TCP créé dans le passé", ->
    m = fresh_ndpi_with_flow!
    -- Créer un buffer TCP avec port unique
    dns = make_dns "\3baz\3qux\0", 1, false, 0xDEF0
    raw = make_ipv4_tcp_dns "192.168.6.1", "8.8.8.8", 59991, 53, dns
    parse_packet raw  -- peuple tcp_buffers
    -- purge avec max_age=0 → expire tout
    ok, err = pcall m.purge_tcp_buffers, 0
    assert.is_true ok, "purge_tcp_buffers(0) apres buffer: " .. tostring(err)

-- ── IPv6 Next Header 59 et inconnu ───────────────────────────────────────────
describe "parse/ndpi — IPv6 Next Header 59 et inconnu", ->

  src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"

  -- Helper : IPv6 minimal 40 B avec NH donné et payload_len=0
  make_ipv6_bare = (nh) ->
    string.char(0x60, 0, 0, 0, 0, 0, nh, 64) .. src6 .. dst6

  it "IPv6 NH=59 (No Next Header) → parse_packet retourne nil", ->
    raw = make_ipv6_bare 59
    pkt = parse_packet raw
    assert.is_nil pkt, "NH=59 doit retourner nil (pas de couche transport)"

  it "IPv6 NH=253 (inconnu) → parse_packet retourne nil", ->
    raw = make_ipv6_bare 253
    pkt = parse_packet raw
    assert.is_nil pkt, "NH=253 (inconnu) doit retourner nil"

  it "IPv6 NH=0 (HBH) trop court → parse_packet retourne nil", ->
    -- Seuls 40 octets : off+2=42 > 40=len → skip_ipv6_ext_hdrs retourne nil
    raw = make_ipv6_bare 0
    pkt = parse_packet raw
    assert.is_nil pkt, "HBH trop court doit retourner nil"

  it "IPv6 NH=0 (HBH) un seul octet → parse_packet retourne nil", ->
    -- 41 octets : off+2=42 > 41 → nil
    raw = make_ipv6_bare(0) .. string.char(17)
    pkt = parse_packet raw
    assert.is_nil pkt, "HBH 1-octet doit retourner nil"

-- ── AH extension header (NH=51) ──────────────────────────────────────────────
describe "parse/ndpi — IPv6 AH extension header (NH=51)", ->

  src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
  dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"

  it "IPv6 + AH (NH=51, len=1 → 12B) + UDP DNS → parse OK", ->
    dns = make_dns "\3www\6github\3com\0", 1, false
    -- AH: NH=17(UDP), len=1 → (1+2)*4=12 octets
    ah = string.char(17, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    raw = make_ipv6_ext_udp_dns src6, dst6, 54326, 53, dns, 51, ah
    pkt = parse_packet raw
    assert.is_not_nil pkt, "parse_packet nil avec AH header"
    assert.equals 6,   pkt.ip.version
    assert.equals "udp", pkt.l4.proto
    assert.equals 0x1234, pkt.dns.txid

-- ── TCP tcp_control (ACK sans données, pas de buffer) ────────────────────────
describe "parse/ndpi — TCP tcp_control (flag RST/FIN, pas de données)", ->

  it "TCP ACK pur (0 payload, pas de buffer) → nil + tcp_control", ->
    src_bytes = "\xC0\xA8\x01\x01"
    dst_bytes = "\x08\x08\x08\x08"
    total_len = 20 + 20
    ip_hdr = string.char(0x45, 0,
      bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF),
      0, 1, 0, 0, 64, 6, 0, 0) .. src_bytes .. dst_bytes
    tcp_hdr = string.char(
      0xD4, 0x31,
      0, 53,
      0, 0, 0, 1,
      0, 0, 0, 0,
      0x50, 0x10,
      0x72, 0x10, 0, 0, 0, 0
    )
    raw = ip_hdr .. tcp_hdr
    pkt, status = parse_packet raw
    assert.is_nil    pkt,          "TCP ACK pur doit retourner nil"
    assert.equals "tcp_control", status, "statut doit être tcp_control"

  it "TCP RST (flag 0x04) sans données → nil + tcp_control", ->
    src_bytes = "\xC0\xA8\x01\x01"
    dst_bytes = "\x08\x08\x08\x08"
    total_len = 20 + 20
    ip_hdr = string.char(0x45, 0,
      bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF),
      0, 1, 0, 0, 64, 6, 0, 0) .. src_bytes .. dst_bytes
    tcp_hdr = string.char(
      0xD4, 0x32,
      0, 53,
      0, 0, 0, 2,
      0, 0, 0, 0,
      0x50, 0x04,
      0x72, 0x10, 0, 0, 0, 0
    )
    raw = ip_hdr .. tcp_hdr
    pkt, status = parse_packet raw
    assert.is_nil    pkt,          "TCP RST sans données → nil"
    assert.equals "tcp_control", status

-- ── patch_and_checksum IPv6 UDP ───────────────────────────────────────────────
describe "parse/ndpi — patch_and_checksum IPv6 UDP (fix_udp6_cksum)", ->

  it "patch_and_checksum sur IPv6 UDP recalcule le checksum correctement", ->
    src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
    dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"

    -- DNS réponse : 1 question + 1 A RR, TTL=300
    qname_enc = "\x03www\x06github\x03com\x00"
    hdr       = string.char(0xAB, 0xCD, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
    question  = qname_enc .. string.char(0, 1, 0, 1)
    rr        = "\xC0\x0C" ..
      string.char(0, 1, 0, 1) ..
      string.char(0, 0, 1, 0x2C) ..
      string.char(0, 4) ..
      string.char(1, 2, 3, 4)
    dns_payload = hdr .. question .. rr

    raw = make_ipv6_udp_dns src6, dst6, 54327, 53, dns_payload
    pkt = parse_packet raw
    assert.is_not_nil pkt, "parse_packet IPv6 UDP retourne nil"
    assert.equals 6,     pkt.ip.version
    assert.equals "udp", pkt.l4.proto

    answers = m_ndpi.parse_answers raw, pkt
    assert.equals 1, #answers, "1 réponse attendue"

    patched = patch_and_checksum raw, pkt, answers, 60
    assert.is_not_nil patched, "patch_and_checksum IPv6 UDP retourne nil"
    assert.equals #raw, #patched, "longueur du paquet inchangée"

-- ── patch_and_checksum IPv6 TCP ───────────────────────────────────────────────
describe "parse/ndpi — patch_and_checksum IPv6 TCP (fix_tcp6_cksum)", ->

  it "patch_and_checksum sur IPv6 TCP fonctionne", ->
    src6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x42"
    dst6 = "\x20\x01\x0d\xb8" .. string.rep("\x00", 11) .. "\x01"

    -- DNS réponse TCP
    qname_enc = "\x03foo\x03bar\x00"
    hdr       = string.char(0xEF, 0x01, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0)
    question  = qname_enc .. string.char(0, 1, 0, 1)
    rr        = "\xC0\x0C" ..
      string.char(0, 1, 0, 1) ..
      string.char(0, 0, 1, 0x2C) ..
      string.char(0, 4) ..
      string.char(5, 6, 7, 8)
    dns_payload = hdr .. question .. rr
    dns_len     = #dns_payload

    -- Construire manuellement un paquet IPv6/TCP/DNS
    pfx = string.char(bit.rshift(bit.band(dns_len, 0xFF00), 8), bit.band(dns_len, 0xFF))
    tcp_payload = pfx .. dns_payload
    pay_len = 20 + #tcp_payload   -- TCP hdr + payload (payloadlen dans IPv6 = tcp + data)
    ip6 = string.char(0x60, 0, 0, 0,
      bit.rshift(bit.band(pay_len, 0xFF00), 8), bit.band(pay_len, 0xFF),
      6, 64) .. src6 .. dst6
    tcp_hdr6 = string.char(
      0xD4, 0x38,
      0, 53,
      0, 0, 0, 1,
      0, 0, 0, 0,
      0x50, 0x18,
      0x72, 0x10, 0, 0, 0, 0
    )
    raw = ip6 .. tcp_hdr6 .. tcp_payload
    pkt = parse_packet raw
    assert.is_not_nil pkt, "parse_packet IPv6 TCP retourne nil"
    assert.equals 6,     pkt.ip.version
    assert.equals "tcp", pkt.l4.proto

    answers = m_ndpi.parse_answers raw, pkt
    patched = patch_and_checksum raw, pkt, answers, 60
    assert.is_not_nil patched, "patch_and_checksum IPv6 TCP retourne nil"
