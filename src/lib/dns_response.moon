-- src/lib/dns_response.moon
-- Fonctions pures de (re)construction et de décodage des réponses DNS, extraites
-- de worker_responses : reconstruction d'un paquet IP avec un nouveau payload DNS
-- (recalcul checksums via lib.checksums) et formatage des RR de réponse.
-- Sans état module — testables unitairement.

ffi = require "ffi"
bit = require "bit"
{ :w16, :w32, :fix_ip4_cksum, :fix_l4_cksum, :PROTO_UDP, :PROTO_TCP } = require "lib.checksums"
{ :ip2s, dns_types: QTYPE } = require "lib.packet_parsing"

-- Reconstruit un paquet IP avec un nouveau payload DNS.
-- ip_ihl : offset 0-based (en octets) de l'en-tête L4 depuis le début du paquet.
replace_dns_payload = (raw, ip, l4, ip_ihl, new_dns) ->
  p       = ffi.cast "const uint8_t*", raw
  dns_len = #new_dns

  if l4.proto == "udp"
    udp_len     = 8 + dns_len
    new_pkt_len = ip_ihl + udp_len
    new_buf = ffi.new "uint8_t[?]", new_pkt_len
    ffi.copy new_buf, p, ip_ihl + 8
    w16 new_buf, ip_ihl + 4, udp_len
    ffi.copy new_buf + ip_ihl + 8, new_dns, dns_len
    if ip.version == 4
      w16 new_buf, 2, new_pkt_len
    else
      w16 new_buf, 4, (ip_ihl - 40) + udp_len
    fix_l4_cksum new_buf, new_pkt_len, ip_ihl, ip.version, PROTO_UDP
    fix_ip4_cksum new_buf, ip_ihl if ip.version == 4
    return ffi.string new_buf, new_pkt_len

  elseif l4.proto == "tcp"
    tcp_hdr_len = bit.rshift(p[ip_ihl + 12], 4) * 4
    hdr_len     = ip_ihl + tcp_hdr_len
    new_pkt_len = hdr_len + 2 + dns_len
    new_buf = ffi.new "uint8_t[?]", new_pkt_len
    ffi.copy new_buf, p, hdr_len
    w16 new_buf, hdr_len, dns_len
    ffi.copy new_buf + hdr_len + 2, new_dns, dns_len
    w32 new_buf, ip_ihl + 4, l4.tcp_init_seq
    new_buf[ip_ihl + 13] = 0x18   -- PSH|ACK
    if ip.version == 4
      w16 new_buf, 2, new_pkt_len
    else
      w16 new_buf, 4, (ip_ihl - 40) + tcp_hdr_len + 2 + dns_len
    fix_l4_cksum new_buf, new_pkt_len, ip_ihl, ip.version, PROTO_TCP
    fix_ip4_cksum new_buf, ip_ihl if ip.version == 4
    return ffi.string new_buf, new_pkt_len

  nil

decode_simple_cname = (rdata) ->
  parts = {}
  pos = 1
  while pos <= #rdata
    len = rdata\byte pos
    break if len == 0
    return "(cname)" if bit.band(len, 0xC0) == 0xC0
    parts[#parts + 1] = rdata\sub pos+1, pos+len
    pos += 1 + len
  table.concat parts, "."

fmt_rdata = (rr) ->
  if (rr.rtype == 1 or rr.rtype == 28) and (#rr.rdata == 4 or #rr.rdata == 16)
    ip2s rr.rdata
  elseif rr.rtype == 5   -- CNAME
    decode_simple_cname rr.rdata
  else
    "(rdata #{#rr.rdata}B)"

parse_answers = (dns_msg) ->
  [ {
    name:       rr.name
    rtype:      rr.rtype
    rclass:     rr.rclass
    ttl:        rr.ttl
    rdlength:   #rr.rdata
    rdata_raw:  (rr.rtype == 1 or rr.rtype == 28) and rr.rdata or ""
    rdata_str:  fmt_rdata rr
    rtype_name: QTYPE[rr.rtype] or "TYPE#{rr.rtype}"
    ttl_offset: rr.off + #rr.rname + 3   -- 0-based depuis début du payload DNS (l7_off=1)
  } for rr in *dns_msg.answers ]

-- Reconstruit une REQUÊTE DNS (QR=0) à partir d'une RÉPONSE : en-tête + section
-- question uniquement. Les drapeaux sont normalisés (QR effacé, RD positionné,
-- RA/Z/RCODE remis à zéro) et les compteurs AN/NS/AR mis à 0. La section question
-- ne contient jamais de compression de nom : on la recopie octet à octet.
-- Sert au retry upstream (worker_responses) pour ré-interroger le même résolveur
-- après une réponse SERVFAIL/REFUSED.
-- @tparam string dns_raw   Payload DNS brut de la réponse.
-- @tparam[opt=1] number qdcount Nombre de questions (header.qdcount).
-- @treturn string|nil Payload DNS de la requête, ou nil si malformé.
build_query_from_response = (dns_raw, qdcount=1) ->
  return nil unless dns_raw and #dns_raw >= 12
  return nil unless qdcount and qdcount >= 1
  off = 13   -- 1-based : premier octet après l'en-tête fixe de 12 octets
  for _ = 1, qdcount
    while true
      return nil if off > #dns_raw
      len = dns_raw\byte off
      off += 1
      break if len == 0
      return nil if bit.band(len, 0xC0) != 0   -- pointeur/label réservé : invalide en question
      off += len
    off += 4   -- QTYPE (2) + QCLASS (2)
    return nil if off - 1 > #dns_raw
  q_end = off - 1
  -- Flags ligne 1 : RD=1, QR=0 ; opcode/aa/tc conservés depuis la réponse.
  b3 = bit.band bit.bor(dns_raw\byte(3), 0x01), 0x7F
  header = string.char dns_raw\byte(1), dns_raw\byte(2), b3, 0x00,
    dns_raw\byte(5), dns_raw\byte(6), 0, 0, 0, 0, 0, 0
  header .. dns_raw\sub 13, q_end

{ :replace_dns_payload, :decode_simple_cname, :fmt_rdata, :parse_answers, :build_query_from_response }
