-- src/forge_dns.moon
-- Forge des réponses DNS pour le vol de question DNS (portail captif).
--
-- Utilisé par worker_questions : quand une question DNS porte sur le hostname du
-- portail captif, on forge la/les réponse(s) et on les injecte directement via
-- AF_PACKET sur le bridge, sans laisser la requête atteindre le résolveur.
--
-- Les paquets retournés sont des paquets IP bruts (sans en-tête Ethernet), avec
-- src/dst inversés par rapport à la question. `forge_dns_response` renvoie une
-- LISTE de paquets :
--   • UDP : un seul datagramme (IP+UDP+DNS) ;
--   • TCP : deux segments — données `PSH+ACK` (préfixe 2 octets de longueur +
--     DNS) puis `FIN+ACK` — la connexion ayant déjà été établie avec le vrai
--     résolveur (la requête interceptée est ensuite droppée par l'appelant).

{ new: new_ip, proto: ip_proto, :s2ip } = require "ipparse.l3.ip"
{ new: new_udp }                         = require "ipparse.l4.udp"
{ new: new_tcp, :flags }                 = require "ipparse.l4.tcp"
dns_mod = require "ipparse.l7.dns"
pack: sp = require "ipparse.lib.pack_compat"
{ :encode_dns_name } = require "lib.dns_name"

PROTO_UDP  = ip_proto.UDP   -- 17
PROTO_TCP  = ip_proto.TCP   -- 6
QTYPE_A    = 1
QTYPE_AAAA = 28
{ :PSH, :ACK, :FIN } = flags

-- Enveloppe IP commune (src/dst inversés) autour d'un objet L4 sérialisable.
-- Le checksum L4 (UDP/TCP) est recalculé par ip_pack via le pseudo-en-tête.
wrap_ip = (ip, l4_obj, proto) ->
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
    protocol:    proto
    next_header: proto
    data:        l4_obj
  }
  "#{ip_pkt}"

-- Encapsule un message DNS dans le transport d'origine ; renvoie une liste de
-- paquets IP bruts prêts à injecter.
encap = (ip, l4, dns_obj) ->
  if l4.proto == "tcp"
    -- DNS-over-TCP : préfixe de longueur sur 2 octets devant le message.
    dns_bytes    = "#{dns_obj}"
    data_payload = sp(">H", #dns_bytes) .. dns_bytes
    -- seq/ack du serveur déduits de la connexion établie (cf. worker_questions).
    server_seq = l4.ack_n
    base_seq   = l4.tcp_init_seq or l4.seq_n
    client_len = l4.tcp_dns_raw and (2 + #l4.tcp_dns_raw) or 0
    server_ack = (base_seq + client_len) % 0x100000000
    mk = (tcp_flags, seq, payload) ->
      tcp = new_tcp {
        spt:        l4.dpt
        dpt:        l4.spt
        seq_n:      seq
        ack_n:      server_ack
        flags:      tcp_flags
        window:     65535
        urg_ptr:    0
        header_len: 0x50   -- 5 mots de 32 bits, aucune option
        options:    ""
        checksum:   0
        data:       payload
      }
      wrap_ip ip, tcp, PROTO_TCP
    {
      mk (PSH + ACK), server_seq, data_payload
      mk (FIN + ACK), (server_seq + #data_payload) % 0x100000000, ""
    }
  else
    udp = new_udp { spt: l4.dpt, dpt: l4.spt, checksum: 0, data: dns_obj }
    { wrap_ip ip, udp, PROTO_UDP }

-- Construit le message DNS (en-tête + question échoyée + answers).
build_dns = (txid, q, answers) ->
  dns_mod.new {
    -- Flags : QR=1, OPCODE=0, AA=1, TC=0, RD=0 | RA=0, Z=0, RCODE=NOERROR
    header: dns_mod.new_header id: txid, qr: true, aa: true
    questions: {{qname: encode_dns_name(q.name), qtype: q.qtype, qclass: 1}}
    answers: answers
  }

--- Forge une réponse DNS A ou AAAA pour un domaine de portail captif volé.
-- Ne gère que QTYPE=A (1) et QTYPE=AAAA (28). Si la famille requise n'est pas
-- configurée, renvoie une réponse NOERROR sans answer (ancount=0) pour que le
-- client tente l'autre famille. Fonctionne en UDP et en TCP.
-- @tparam table    ip      En-tête IP parsé (ipparse.l3.ip4 ou ip6).
-- @tparam table    l4      En-tête UDP ou TCP parsé (champ .proto = "udp"|"tcp").
-- @tparam number   txid    DNS transaction ID.
-- @tparam table    q       Question DNS {name, qtype}.
-- @tparam string|nil ip4_str Adresse IPv4 du portail captif, ou nil.
-- @tparam string|nil ip6_str Adresse IPv6 du portail captif, ou nil.
-- @treturn table|nil Liste de paquets IP bruts (IP+L4+DNS, sans Ethernet), ou nil.
forge_dns_response = (ip, l4, txid, q, ip4_str, ip6_str) ->
  return nil unless q.qtype == QTYPE_A or q.qtype == QTYPE_AAAA

  -- ── Détermination du rdata ──────────────────────────────────
  local rdata
  if q.qtype == QTYPE_A and ip4_str
    ok, raw = pcall s2ip, ip4_str
    rdata = raw if ok and raw and #raw == 4
  elseif q.qtype == QTYPE_AAAA and ip6_str
    ok, raw = pcall s2ip, ip6_str
    rdata = raw if ok and raw and #raw == 16

  answers = rdata and {{rname: "\xC0\x0C", rtype: q.qtype, rclass: 1, rdata: rdata}} or {}
  encap ip, l4, build_dns txid, q, answers

{ :forge_dns_response }
