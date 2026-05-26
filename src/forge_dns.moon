-- src/forge_dns.moon
-- Forge des réponses DNS pour le vol de question DNS (portail captif).
--
-- Utilisé par worker_questions (question) : quand une question DNS porte sur le
-- hostname du portail captif, question appelle forge_dns_response et injecte la
-- réponse forgée directement via nfq_set_verdict, sans la laisser atteindre
-- le resolver. response n'est pas impliqué (pas de message IPC).
--
-- Le paquet retourné est un paquet IP+UDP brut (sans Ethernet header) avec
-- src/dst inversés par rapport à la question d'origine, compatible avec
-- nfq_set_verdict(NF_ACCEPT, payload, len) sur un hook bridge nftables.
-- La même mécanique empirique que worker_reject (reject) permet au bridge de
-- router le paquet vers le client.

{ new: new_ip, proto: ip_proto, :s2ip } = require "ipparse.l3.ip"
{ new: new_udp }                         = require "ipparse.l4.udp"
dns_mod = require "ipparse.l7.dns"
pack: sp = require "ipparse.lib.pack_compat"

PROTO_UDP  = ip_proto.UDP   -- 17
QTYPE_A    = 1
QTYPE_AAAA = 28

--- Encode a domain name in DNS wire format.
-- "example.com" → "\x07example\x03com\x00"
-- Trailing dots are stripped before encoding.
-- @tparam string name Domain name in dotted notation
-- @treturn string Binary DNS wire-format name
encode_dns_name = (name) ->
  name = name\gsub "%.+$", ""
  parts = {}
  for label in name\gmatch "[^.]+"
    parts[#parts + 1] = string.char(#label) .. label
  table.concat(parts) .. "\x00"

--- Forge a DNS A or AAAA response for a stolen captive-portal domain query.
-- Only handles QTYPE=A (1) and QTYPE=AAAA (28); returns nil for other types.
-- If the required IP family is not configured, returns an NOERROR response
-- with ancount=0 (empty answer section) rather than nil, so the client can
-- try the other address family.
-- @tparam table    ip      Parsed IP header (ipparse.l3.ip4 or ip6).
-- @tparam table    udp     Parsed UDP header (ipparse.l4.udp).
-- @tparam number   txid    DNS transaction ID.
-- @tparam table    q       DNS question {name, qtype} from ipparse.l7.dns.
-- @tparam string|nil ip4_str Captive portal IPv4 address string (e.g. "192.168.1.1"), or nil
-- @tparam string|nil ip6_str Captive portal IPv6 address string (e.g. "fd00::1"), or nil
-- @treturn string|nil Forged raw IP packet (IP+UDP+DNS, no Ethernet), or nil on error/unsupported
forge_dns_response = (ip, udp, txid, q, ip4_str, ip6_str) ->
  return nil unless q.qtype == QTYPE_A or q.qtype == QTYPE_AAAA

  -- ── Détermination du rdata ──────────────────────────────────
  local rdata
  ancount = 0

  if q.qtype == QTYPE_A and ip4_str
    ok, raw = pcall s2ip, ip4_str
    if ok and raw and #raw == 4
      rdata   = raw
      ancount = 1
  elseif q.qtype == QTYPE_AAAA and ip6_str
    ok, raw = pcall s2ip, ip6_str
    if ok and raw and #raw == 16
      rdata   = raw
      ancount = 1
  -- Sinon : NOERROR sans réponse (ancount = 0) — famille non configurée

  -- ── Payload DNS ─────────────────────────────────────────────
  -- Flags : QR=1, OPCODE=0, AA=1, TC=0, RD=0 | RA=0, Z=0, RCODE=NOERROR
  dns_obj = dns_mod.new {
    header: dns_mod.new_header id: txid, qr: true, aa: true
    questions: {{qname: encode_dns_name(q.name), qtype: q.qtype, qclass: 1}}
    answers: ancount == 1 and {{rname: "\xC0\x0C", rtype: q.qtype, rclass: 1, rdata: rdata}} or {}
  }

  -- ── Datagramme UDP et IP ─────────────────────────────────────
  -- src/dst inversés par rapport à la question (réponse vers le client).
  l4 = new_udp { spt: udp.dpt, dpt: udp.spt, checksum: 0, data: dns_obj }
  ip_pkt = new_ip {
    version:     ip.version
    -- IPv4
    v_ihl:       ip.v_ihl
    tos:         ip.tos
    id:          ip.id
    ff:          ip.ff
    ttl:         ip.ttl
    options:     ip.options or ""
    -- IPv6
    vtf:         ip.vtf
    hop_limit:   ip.hop_limit
    -- commun
    src:         ip.dst
    dst:         ip.src
    protocol:    PROTO_UDP
    next_header: PROTO_UDP
    data:        l4
  }
  "#{ip_pkt}"

{ :forge_dns_response }
