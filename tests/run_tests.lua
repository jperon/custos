-- tests/run_tests.lua
-- Tests unitaires pour les modules de parsing et IPC.
-- Exécutable sans root, sans libnetfilter_queue, sans libnftables.
-- Charge les modules de parsing directement (pas de require("ffi_defs")).

local bit = require("bit")
local ffi = require("ffi")

-- ── Stubs globaux injectés avant tout dofile ─────────────────────
-- Empêche ffi_defs de tenter de charger libnetfilter_queue.so /
-- libnftables.so, absents de l'environnement de test unitaire.
-- Les modules de parsing n'utilisent que ffi.new/ffi.cast (builtins JIT),
-- pas libnfq ni libnft.
package.loaded["ffi_defs"] = {
  ffi    = ffi,
  libc   = ffi.C,
  libnfq = {},
  libnft = {},
}
package.loaded["config"] = {
  PROTO_UDP       = 17,
  AF_INET         = 2,
  AF_INET6        = 10,
  DNS_PORT        = 53,
  DOCKER_MODE     = false,
  ALLOWED_DOMAINS = {},
  IPC_MSG_SIZE    = 21,
  IPC_PENDING_TTL = 5,
}

-- ── Mini framework de test ───────────────────────────────────────
local passed, failed = 0, 0

local function eq(a, b)
  if type(a) == "table" and type(b) == "table" then
    for k, v in pairs(b) do
      if a[k] ~= v then return false end
    end
    return true
  end
  return a == b
end

local function test(name, fn)
  local ok, err = pcall(fn)
  if ok then
    passed = passed + 1
    io.write(string.format("  OK   %s\n", name))
  else
    failed = failed + 1
    io.write(string.format("  FAIL %s\n       %s\n", name, tostring(err)))
  end
end

local function assert_eq(got, expected, msg)
  if not eq(got, expected) then
    error(string.format("%s\n       got:      %s\n       expected: %s",
      msg or "", tostring(got), tostring(expected)), 2)
  end
end

-- ── Helpers de construction de paquets de test ───────────────────

-- Construit un message DNS minimal (header + 1 question)
-- qname_encoded : string Lua encodée en labels DNS (ex: "\3www\8facebook\3com\0")
-- is_response   : bool
-- txid          : uint16
local function make_dns(qname_encoded, qtype, is_response, txid)
  txid = txid or 0x1234
  qtype = qtype or 1  -- A
  local flags_hi = is_response and 0x81 or 0x01  -- RD=1
  local flags_lo = 0x00
  local hdr = string.char(
    bit.rshift(bit.band(txid, 0xFF00), 8), bit.band(txid, 0xFF),
    flags_hi, flags_lo,
    0, 1,   -- qdcount = 1
    0, 0,   -- ancount = 0
    0, 0,   -- nscount
    0, 0    -- arcount
  )
  local qsection = qname_encoded
    .. string.char(0, qtype, 0, 1)  -- qtype + qclass IN
  return hdr .. qsection
end

-- Construit un paquet IPv4/UDP/DNS minimal
local function make_ipv4_udp_dns(src_ip, dst_ip, src_port, dst_port, dns_payload)
  -- IP header minimal (20 octets, sans options)
  local total_len = 20 + 8 + #dns_payload
  local ihl_ver = 0x45  -- version=4, ihl=5 (20 octets)
  local ip = string.char(
    ihl_ver, 0,
    bit.rshift(bit.band(total_len, 0xFF00), 8), bit.band(total_len, 0xFF),
    0, 1,   -- id
    0, 0,   -- flags + fragment offset
    64,     -- TTL
    17,     -- protocol UDP
    0, 0    -- checksum (non calculé pour les tests)
  )
  -- src_ip et dst_ip : strings "a.b.c.d"
  local function ip4bytes(s)
    local a, b, c, d = s:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    return string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
  end
  ip = ip .. ip4bytes(src_ip) .. ip4bytes(dst_ip)

  -- UDP header (8 octets)
  local udp_len = 8 + #dns_payload
  local udp = string.char(
    bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF),
    bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF),
    bit.rshift(bit.band(udp_len,  0xFF00), 8), bit.band(udp_len,  0xFF),
    0, 0    -- checksum
  )

  return ip .. udp .. dns_payload
end

-- Construit un paquet IPv6/UDP/DNS minimal (40B IPv6 + 8B UDP + payload)
local function make_ipv6_udp_dns(src_ip6, dst_ip6, src_port, dst_port, dns_payload)
  -- src_ip6 / dst_ip6 : strings de 16 octets bruts
  local udp_len   = 8 + #dns_payload
  local pay_len   = udp_len   -- IPv6 payload length = udp_len (pas d'ext header)
  local ip6 = string.char(
    0x60, 0, 0, 0,    -- version=6, traffic class=0, flow label=0
    bit.rshift(bit.band(pay_len, 0xFF00), 8), bit.band(pay_len, 0xFF),
    17,               -- next header = UDP
    64                -- hop limit
  ) .. src_ip6 .. dst_ip6

  -- UDP header (8 octets)
  local udp = string.char(
    bit.rshift(bit.band(src_port, 0xFF00), 8), bit.band(src_port, 0xFF),
    bit.rshift(bit.band(dst_port, 0xFF00), 8), bit.band(dst_port, 0xFF),
    bit.rshift(bit.band(udp_len,  0xFF00), 8), bit.band(udp_len,  0xFF),
    0, 0    -- checksum (sera rempli par le test)
  )

  return ip6 .. udp .. dns_payload
end

-- ════════════════════════════════════════════════════════════════
-- Tests parse/ip
-- ════════════════════════════════════════════════════════════════
io.write("\n── parse/ip ──\n")

-- Charge le module directement (inline pour éviter require chain)
local read_u8, read_u16, read_u32, format_ipv4, parse_ipv4, parse_ipv6
do
  local m = dofile("lua/parse/ip.lua")
  read_u8    = m.read_u8
  read_u16   = m.read_u16
  read_u32   = m.read_u32
  format_ipv4 = m.format_ipv4
  parse_ipv4 = m.parse_ipv4
  parse_ipv6 = m.parse_ipv6
end

test("read_u16 big-endian", function()
  local s = "\x12\x34\x56\x78"
  assert_eq(read_u16(s, 1), 0x1234, "offset 1")
  assert_eq(read_u16(s, 3), 0x5678, "offset 3")
end)

test("read_u32 big-endian", function()
  local s = "\xDE\xAD\xBE\xEF"
  assert_eq(read_u32(s, 1), 0xDEADBEEF, "u32")
end)

test("format_ipv4", function()
  local s = "\xC0\xA8\x01\x01"  -- 192.168.1.1
  assert_eq(format_ipv4(s, 1), "192.168.1.1", "format")
end)

test("parse_ipv4 — paquet UDP minimal", function()
  local dns    = make_dns("\3www\6github\3com\0", 1, false)
  local raw    = make_ipv4_udp_dns("192.168.1.42", "8.8.8.8", 54321, 53, dns)
  local ip_hdr = parse_ipv4(raw)
  assert(ip_hdr, "parse_ipv4 retourne nil")
  assert_eq(ip_hdr.version,  4,              "version")
  assert_eq(ip_hdr.ihl,      20,             "ihl")
  assert_eq(ip_hdr.protocol, 17,             "proto UDP")
  assert_eq(ip_hdr.src_ip,   "192.168.1.42", "src_ip")
  assert_eq(ip_hdr.dst_ip,   "8.8.8.8",      "dst_ip")
end)

test("parse_ipv4 — paquet trop court → nil", function()
  assert_eq(parse_ipv4("\x45\x00\x00"), nil, "trop court")
end)

-- ════════════════════════════════════════════════════════════════
-- Tests parse/dns
-- ════════════════════════════════════════════════════════════════
io.write("\n── parse/dns ──\n")

local decode_name, parse_dns, QTYPE, RCODE, patch_ttl, build_refused
do
  -- parse/ip doit être dans package.loaded pour que parse/dns puisse le trouver via require
  package.loaded["parse/ip"] = dofile("lua/parse/ip.lua")
  local m = dofile("lua/parse/dns.lua")
  decode_name  = m.decode_name
  parse_dns    = m.parse_dns
  QTYPE        = m.QTYPE
  RCODE        = m.RCODE
  patch_ttl    = m.patch_ttl
  build_refused = m.build_refused
end

test("decode_name — labels simples", function()
  local buf = "\3www\8facebook\3com\0"
  local name, consumed = decode_name(buf, 1)
  assert_eq(name,     "www.facebook.com", "name")
  assert_eq(consumed, #buf,               "consumed")
end)

test("decode_name — pointeur de compression", function()
  -- Un message DNS réaliste : header 12B + question "foo.bar" + RR avec pointeur.
  -- On construit un buffer où :
  --   offset 0-based 0  = '\x03foo\x03bar\x00' (9 octets)
  --   offset 0-based 9  = pointeur 0xC0 0x00 → renvoie à l'offset 0 = "foo.bar"
  -- En 1-based Lua : base commence à pos 1, pointeur à pos 10.
  local base = "\x03foo\x03bar\x00"   -- 9 octets (offset 0-based : 0..8)
  local ptr  = "\xC0\x00"             -- 0xC0 0x00 : pointe sur offset 0-based 0
  local buf  = base .. ptr            -- 11 octets
  -- On demande le nom à partir du pointeur (pos 1-based = 10)
  local name, consumed = decode_name(buf, 10)
  assert_eq(name,     "foo.bar", "compressed name")
  assert_eq(consumed, 2,         "consumed = 2 (juste le pointeur)")
end)

test("decode_name — protection boucle infinie", function()
  -- Pointeurs circulaires : offset 0 → offset 2 → offset 0 → ...
  -- buf[0-based] : 0xC0 0x02 | 0xC0 0x00
  -- En 1-based : pos 1 = 0xC0, pos 2 = 0x02 → ptr = offset 0-based 2 → pos 1-based 3
  --              pos 3 = 0xC0, pos 4 = 0x00 → ptr = offset 0-based 0 → pos 1-based 1  (boucle)
  local buf = "\xC0\x02\xC0\x00"
  local name, consumed = decode_name(buf, 1)
  assert_eq(name, nil, "boucle circulaire detectee → nil")
end)

test("parse_dns — question A www.github.com", function()
  local qname = "\3www\6github\3com\0"
  local dns_payload = make_dns(qname, QTYPE.A, false, 0xABCD)
  local parsed = parse_dns(dns_payload)
  assert(parsed, "parse_dns nil")
  assert_eq(parsed.hdr.txid,        0xABCD,     "txid")
  assert_eq(parsed.hdr.is_response, false,       "is_response")
  assert_eq(parsed.hdr.qdcount,     1,           "qdcount")
  assert_eq(#parsed.questions,      1,           "1 question")
  assert_eq(parsed.questions[1].qname, "www.github.com", "qname")
  assert_eq(parsed.questions[1].qtype, QTYPE.A,          "qtype A")
end)

test("parse_dns — réponse avec RR A", function()
  -- Construit une réponse avec 1 RR de type A (1.2.3.4)
  local qname_enc = "\6github\3com\0"
  local txid  = 0x5678
  -- Header : réponse, 1 question, 1 answer
  local hdr = string.char(
    0x56, 0x78,   -- txid
    0x81, 0x80,   -- QR=1 RD=1 RA=1
    0, 1,         -- qdcount
    0, 1,         -- ancount
    0, 0, 0, 0
  )
  local question = qname_enc .. string.char(0, 1, 0, 1)  -- A IN
  -- RR : pointeur vers qname (offset 12, 0-based → 0xC00C), A, IN, TTL=300, RDATA=1.2.3.4
  local rr = "\xC0\x0C"  -- pointeur vers offset 12 (début question)
    .. string.char(0, 1, 0, 1)          -- type A, class IN
    .. string.char(0, 0, 1, 0x2C)       -- TTL = 300
    .. string.char(0, 4)                -- rdlength = 4
    .. string.char(1, 2, 3, 4)          -- 1.2.3.4

  local dns_payload = hdr .. question .. rr
  local parsed = parse_dns(dns_payload)
  assert(parsed, "parse_dns nil")
  assert_eq(parsed.hdr.is_response, true,  "is_response")
  assert_eq(parsed.hdr.ancount,     1,     "ancount")
  assert_eq(#parsed.answers,        1,     "1 answer")
  assert_eq(parsed.answers[1].rdata_str, "1.2.3.4", "rdata_str")
  assert_eq(parsed.answers[1].rtype,     QTYPE.A,   "rtype A")
  assert_eq(parsed.answers[1].ttl,       300,        "ttl original")
end)

test("build_refused -- header REFUSED + EDE OPT", function()
  local qname   = "\8facebook\3com\0"   -- 13 octets
  local dns_buf = make_dns(qname, QTYPE.A, false, 0xBEEF)
  local dns_obj = parse_dns(dns_buf)
  assert(dns_obj, "parse_dns nil")
  local refused = build_refused(dns_obj, dns_buf)
  assert(refused, "build_refused nil")
  local resp = parse_dns(refused)
  assert(resp, "parse_dns sur la reponse REFUSED nil")
  assert_eq(resp.hdr.txid,        0xBEEF, "txid copié")
  assert_eq(resp.hdr.is_response, true,   "QR=1")
  assert_eq(resp.hdr.rcode,       RCODE.REFUSED, "RCODE=5 REFUSED")
  assert_eq(resp.hdr.qdcount,     1,      "qdcount copié")
  assert_eq(resp.hdr.ancount,     0,      "ancount=0")
  assert_eq(resp.hdr.arcount,     1,      "arcount=1 EDNS OPT")
  assert_eq(#resp.questions,      1,      "1 question copiée")
  assert_eq(resp.questions[1].qname, "facebook.com", "qname copié")
end)

test("build_refused -- OPT RR EDE bytes", function()
  local qname   = "\3foo\3com\0"         -- 9 octets
  local dns_buf = make_dns(qname, QTYPE.A, false, 0x1234)
  local dns_obj = parse_dns(dns_buf)
  local refused = build_refused(dns_obj, dns_buf)
  assert(refused, "build_refused nil")
  -- Question section = qname (9B) + type(2) + class(2) = 13B
  -- OPT RR starts at offset 12 (header) + 13 (question) + 1 = 26 (1-based)
  local q_len     = #qname + 4   -- qname + qtype(2) + qclass(2)
  local opt_start = 12 + q_len + 1   -- 1-based
  assert_eq(refused:byte(opt_start),    0x00, "OPT NAME = root")
  assert_eq(refused:byte(opt_start+1),  0x00, "OPT TYPE hi")
  assert_eq(refused:byte(opt_start+2),  0x29, "OPT TYPE lo = 41")
  assert_eq(refused:byte(opt_start+9),  0x00, "RDLEN hi")
  assert_eq(refused:byte(opt_start+10), 0x06, "RDLEN lo = 6")
  assert_eq(refused:byte(opt_start+11), 0x00, "EDE opt-code hi")
  assert_eq(refused:byte(opt_start+12), 0x0F, "EDE opt-code lo = 15")
  assert_eq(refused:byte(opt_start+13), 0x00, "EDE opt-len hi")
  assert_eq(refused:byte(opt_start+14), 0x02, "EDE opt-len lo = 2")
  assert_eq(refused:byte(opt_start+15), 0x00, "EDE info-code hi")
  assert_eq(refused:byte(opt_start+16), 0x0F, "EDE info-code lo = 15 Filtered")
end)


-- ════════════════════════════════════════════════════════════════
-- Tests parse/udp  (pseudo-header IPv4 et IPv6, checksum)
-- ════════════════════════════════════════════════════════════════
io.write("\n-- parse/udp --\n")

local parse_udp, checksum_udp, pseudo_header_sum_v4, pseudo_header_sum_v6
do
  package.loaded["parse/ip"] = dofile("lua/parse/ip.lua")
  local m = dofile("lua/parse/udp.lua")
  parse_udp            = m.parse_udp
  checksum_udp         = m.checksum_udp
  pseudo_header_sum_v4 = m.pseudo_header_sum_v4
  pseudo_header_sum_v6 = m.pseudo_header_sum_v6
end

test("pseudo_header_sum_v4 — somme connue", function()
  local src = "\xC0\xA8\x01\x2A"  -- 192.168.1.42
  local dst = "\x08\x08\x08\x08"  -- 8.8.8.8
  local s   = pseudo_header_sum_v4(src, dst, 100)
  -- 0xC0A8 + 0x012A + 0x0808 + 0x0808 + 17 + 100
  local expected = 0xC0A8 + 0x012A + 0x0808 + 0x0808 + 17 + 100
  assert_eq(s, expected, "somme pseudo-header v4")
end)

test("pseudo_header_sum_v6 -- 16 octets non tronques", function()
  -- 2001:db8::1 -> src, 2001:db8::2 -> dst
  local src = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  local dst = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
  local s   = pseudo_header_sum_v6(src, dst, 60)
  -- src words : 0x2001 + 0x0db8 + 0*6 + 0x0001 = 0x2DBA
  -- dst words : 0x2001 + 0x0db8 + 0*6 + 0x0002 = 0x2DBB
  -- + udp_len=60 + next_header=17
  local expected = 0x2DBA + 0x2DBB + 60 + 17
  assert_eq(s, expected, "somme pseudo-header v6")
end)

test("checksum_udp IPv4 -- not zero", function()
  local dns     = make_dns("\x03www\x06github\x03com\x00", 1, false)
  local raw     = make_ipv4_udp_dns("192.168.1.42", "8.8.8.8", 54321, 53, dns)
  local ip_m    = dofile("lua/parse/ip.lua")
  local udp_m   = dofile("lua/parse/udp.lua")
  local ip_hdr  = ip_m.parse_ipv4(raw)
  local udp_hdr = udp_m.parse_udp(raw, ip_hdr)
  local cksum   = checksum_udp(raw, ip_hdr, udp_hdr)
  assert(cksum ~= 0, "checksum IPv4 non nul")
  assert(cksum <= 0xFFFF, "checksum <= 0xFFFF")
end)

test("checksum_udp IPv6 -- non nul et different du checksum IPv4 meme payload", function()
  local dns = make_dns("\x06github\x03com\x00", 1, false)
  local src6 = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42"
  local dst6 = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
  local raw6  = make_ipv6_udp_dns(src6, dst6, 54321, 53, dns)
  local raw4  = make_ipv4_udp_dns("192.168.1.42", "8.8.8.8", 54321, 53, dns)
  local ip_m  = dofile("lua/parse/ip.lua")
  local udp_m = dofile("lua/parse/udp.lua")
  local ip6_hdr  = ip_m.parse_ipv6(raw6)
  local udp6_hdr = udp_m.parse_udp(raw6, ip6_hdr)
  local ip4_hdr  = ip_m.parse_ipv4(raw4)
  local udp4_hdr = udp_m.parse_udp(raw4, ip4_hdr)
  local ck6 = checksum_udp(raw6, ip6_hdr, udp6_hdr)
  local ck4 = checksum_udp(raw4, ip4_hdr, udp4_hdr)
  assert(ck6 ~= 0, "checksum IPv6 non nul")
  assert(ck6 <= 0xFFFF, "checksum IPv6 <= 0xFFFF")
  assert(ck6 ~= ck4, "checksum IPv6 != checksum IPv4 (pseudo-headers differents)")
end)


io.write("\n── allowlist ──\n")

-- Test de la logique de correspondance par suffixe (sans les signaux POSIX)
local function make_is_allowed(domains)
  local set = {}
  for _, d in ipairs(domains) do set[d:lower()] = true end
  return function(qname)
    local name = qname:lower()
    if set[name] then return true end
    -- find(".", pos, true) : 3ème arg true = plain search (pas un pattern Lua)
    local pos = name:find(".", 1, true)
    while pos do
      local suffix = name:sub(pos + 1)
      if set[suffix] then return true end
      pos = name:find(".", pos + 1, true)
    end
    return false
  end
end

local allowed = {
  "github.com", "debian.org", "cloudflare.com", "local", "home.arpa"
}
local is_allowed = make_is_allowed(allowed)

local cases = {
  { "www.github.com",          true  },
  { "github.com",              true  },
  { "api.github.com",          true  },
  { "sub.api.github.com",      true  },
  { "notgithub.com",           false },
  { "evil.com",                false },
  { "www.evil.github.com.evil.com", false },
  { "debian.org",              true  },
  { "ftp.debian.org",          true  },
  { "ubuntu.com",              false },  -- pas dans la liste
  { "myhost.local",            true  },
  { "gateway.home.arpa",       true  },
}

for _, c in ipairs(cases) do
  test(string.format("allowlist(%s) == %s", c[1], tostring(c[2])), function()
    assert_eq(is_allowed(c[1]), c[2], c[1])
  end)
end

-- ════════════════════════════════════════════════════════════════
-- Tests ipc — encodage/décodage des messages pipe
-- ════════════════════════════════════════════════════════════════
io.write("\n── ipc ──\n")

local encode_msg, decode_msg, make_key
do
  -- Invalider le cache pour forcer le rechargement propre du module
  package.loaded["ipc"] = nil
  package.loaded["log"] = {
    log_warn = function() end, log_error = function() end,
    log_info = function() end, now = function() return os.time() end,
  }
  local m = dofile("lua/ipc.lua")
  encode_msg = m.encode_msg
  decode_msg = m.decode_msg
  make_key   = m.make_key
end

test("encode/decode IPv4 round-trip", function()
  local ip_raw  = "\xC0\xA8\x01\x2A"  -- 192.168.1.42
  local txid    = 0x1234
  local port    = 54321
  local msg     = encode_msg(txid, ip_raw, port)
  assert_eq(#msg, 21, "taille message = 21")
  local decoded = decode_msg(msg)
  assert(decoded, "decode_msg nil")
  assert_eq(decoded.txid,     txid,          "txid")
  assert_eq(decoded.src_port, port,          "port")
  assert_eq(decoded.ip_str,   "192.168.1.42","ip_str")
  assert_eq(decoded.msg_type, 0x41,          "type IPv4")
end)

test("encode/decode IPv6 round-trip", function()
  local ip_raw = "\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01" -- 2001:db8::1
  local txid   = 0xABCD
  local port   = 5353
  local msg    = encode_msg(txid, ip_raw, port)
  assert_eq(#msg, 21, "taille message = 21")
  local decoded = decode_msg(msg)
  assert(decoded, "decode_msg nil")
  assert_eq(decoded.txid,     txid,                  "txid")
  assert_eq(decoded.src_port, port,                  "port")
  assert_eq(decoded.ip_str,   "2001:db8:0:0:0:0:0:1","ip_str")
  assert_eq(decoded.msg_type, 0x36,                  "type IPv6")
end)

test("make_key — unicité", function()
  local k1 = make_key(0x1234, "192.168.1.1", 53)
  local k2 = make_key(0x1234, "192.168.1.2", 53)
  local k3 = make_key(0x5678, "192.168.1.1", 53)
  assert(k1 ~= k2, "ip différentes → clés différentes")
  assert(k1 ~= k3, "txid différents → clés différentes")
end)

-- ════════════════════════════════════════════════════════════════
-- Résumé
-- ════════════════════════════════════════════════════════════════
io.write(string.format(
  "\n%d test(s) passé(s), %d échec(s)\n",
  passed, failed
))
os.exit(failed == 0 and 0 or 1)
