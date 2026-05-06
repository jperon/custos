-- src/forge_dns.moon
-- Forge des réponses DNS pour le vol de question DNS (portail captif).
--
-- Utilisé par worker_questions (Q0) : quand une question DNS porte sur le
-- hostname du portail captif, Q0 appelle forge_dns_response et injecte la
-- réponse forgée directement via nfq_set_verdict, sans la laisser atteindre
-- le resolver. Q1 n'est pas impliqué (pas de message IPC).
--
-- Le paquet retourné est un paquet IP+UDP brut (sans Ethernet header) avec
-- src/dst inversés par rapport à la question d'origine, compatible avec
-- nfq_set_verdict(NF_ACCEPT, payload, len) sur un hook bridge nftables.
-- La même mécanique empirique que worker_reject (Q3) permet au bridge de
-- router le paquet vers le client.

{ new: new_ip, proto: ip_proto, :s2ip } = require "ipparse.l3.ip"
{ new: new_udp }                         = require "ipparse.l4.udp"
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
-- Only handles UDP DNS; returns nil for TCP DNS.
-- If the required IP family is not configured, returns an NOERROR response
-- with ancount=0 (empty answer section) rather than nil, so the client can
-- try the other address family.
-- @tparam table    pkt     Parsed packet from parse/packet.parse_packet
-- @tparam table    q       DNS question {qname, qtype, qtype_name}
-- @tparam string|nil ip4_str Captive portal IPv4 address string (e.g. "192.168.1.1"), or nil
-- @tparam string|nil ip6_str Captive portal IPv6 address string (e.g. "fd00::1"), or nil
-- @treturn string|nil Forged raw IP packet (IP+UDP+DNS, no Ethernet), or nil on error/unsupported
forge_dns_response = (pkt, q, ip4_str, ip6_str) ->
  return nil unless q.qtype == QTYPE_A or q.qtype == QTYPE_AAAA
  return nil if pkt.l4.proto != "udp"   -- TCP DNS non géré

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
  -- qr_opcode_aa_tc_rd = 0x84  (10000100)
  -- ra_z_rcode         = 0x00  (00000000)
  dns_hdr  = sp ">H BB HHHH", pkt.dns.txid, 0x84, 0x00, 1, ancount, 0, 0

  -- Section Question : ré-encodage du nom en wire format, type et classe IN
  question = encode_dns_name(q.qname) .. sp(">HH", q.qtype, 1)

  -- Section Answer : pointeur de compression 0xC00C → offset 12 dans le message DNS
  -- (début du nom dans la section Question, juste après le header de 12 octets)
  answer = if ancount == 1
    "\xC0\x0C" .. sp(">HH I4 s2", q.qtype, 1, 60, rdata)
  else
    ""

  dns_payload = dns_hdr .. question .. answer

  -- ── Datagramme UDP (ports inversés) ─────────────────────────
  -- spt = port resolver (53) → apparaît comme source de la réponse
  -- dpt = port éphémère du client → destination de la réponse
  udp_obj = new_udp {
    spt:      pkt.l4.dst_port   -- 53 (port du resolver)
    dpt:      pkt.l4.src_port   -- port éphémère du client
    checksum: 0                  -- calculé par ip4/ip6 pack
    data:     dns_payload
  }

  -- ── Paquet IP (src/dst inversés) ────────────────────────────
  -- src = IP du resolver → le paquet semble venir du resolver
  -- dst = IP du client   → destinataire de la réponse forgée
  -- La même mécanique empirique que Q3 (worker_reject) délivre le paquet
  -- au client via le bridge, même si le header L2 original n'est pas modifié.
  local ip_obj
  if pkt.ip.version == 6
    ip_obj = new_ip {
      version:     6
      hop_limit:   64
      next_header: PROTO_UDP
      src:         pkt.ip.dst_ip_raw   -- IP resolver (src de la réponse)
      dst:         pkt.ip.src_ip_raw   -- IP client   (dst de la réponse)
      data:        udp_obj
    }
  else
    ip_obj = new_ip {
      version:  4
      ttl:      64
      protocol: PROTO_UDP
      src:      pkt.ip.dst_ip_raw   -- IP resolver (src de la réponse)
      dst:      pkt.ip.src_ip_raw   -- IP client   (dst de la réponse)
      options:  ""
      data:     udp_obj
    }

  "#{ip_obj}"

{ :forge_dns_response }
