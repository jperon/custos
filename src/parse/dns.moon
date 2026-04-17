-- src/parse/dns.moon
-- Décodage L7 : DNS (RFC 1035 + compression RFC 1035 §4.1.4).
-- Couvre : header, questions (qname/qtype/qclass), resource records (A, AAAA).
-- Fournit aussi le patch in-place du TTL sur les réponses.

{ :read_u8, :read_u16, :read_u32 } = require "parse/ip"
bit = require "bit"

-- ── Constantes DNS ───────────────────────────────────────────────

-- Bit QR dans le champ flags (octet 3, bit 7)
QR_BIT     = 0x80   -- 1 = réponse, 0 = question
OPCODE_MASK = 0x78  -- bits 3-6 de l'octet flags

-- Qtypes courants
QTYPE = {
  A:     1
  NS:    2
  CNAME: 5
  SOA:   6
  MX:    15
  AAAA:  28
  TXT:   16
  SRV:   33
  ANY:   255
}
QTYPE_NAME = {}
for k, v in pairs QTYPE
  QTYPE_NAME[v] = k

-- RCODE (octet 4, 4 bits bas)
RCODE = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5 }

-- EDNS type OPT (RFC 6891)
QTYPE_OPT = 41

-- Code EDE « Filtered » (RFC 8914 §5.16) — réponses bloquées
EDE_FILTERED = 15

-- Code EDE « Other » (RFC 8914 §5.1) — réponses acceptées avec TTL modifié
EDE_OTHER = 0

-- Message additionnel EDE (RFC 8914 §4, champ extra-text UTF-8 après l'info-code)
EDE_EXTRA_TEXT = "Ne intretis."

-- Message EDE pour les réponses dont le TTL est modifié par custos
EDE_TTL_TEXT = "Custos vigilat."

-- OPTION-CODEs EDNS (RFC 6891 §6.1.2 / RFC 8914 §4)
EDNS_OPT_EDE  = 0x000F   -- EDE option (RFC 8914, valeur assignée par IANA)

-- Options draft-muks-dns-filtering-02 : codes TBD (IANA non encore alloué).
-- Valeur 0 → ignoré par build_opt_rdata (skip automatique).
EDNS_OPT_LANG = 0   -- EDE-EXTRA-TEXT-LANGUAGE (draft-muks TBD)
EDNS_OPT_FORG = 0   -- FILTERING-ORGANIZATION  (draft-muks TBD)

-- Valeurs des options filtering (draft-muks-dns-filtering-02)
FILTER_LANG = "la"       -- Latin (RFC 5646)
FILTER_ORG  = "custos"

-- ── Header DNS (12 octets) ───────────────────────────────────────
--   0-1  : txid
--   2    : flags high (QR + OPCODE + AA + TC + RD)
--   3    : flags low  (RA + Z + RCODE)
--   4-5  : QDCOUNT
--   6-7  : ANCOUNT
--   8-9  : NSCOUNT
--   10-11: ARCOUNT

parse_header = (buf) ->
  return nil if #buf < 12
  flags_hi = read_u8 buf, 3
  flags_lo = read_u8 buf, 4
  {
    txid:    read_u16 buf, 1
    is_response: bit.band(flags_hi, QR_BIT) != 0
    opcode:  bit.rshift bit.band(flags_hi, OPCODE_MASK), 3
    aa:      bit.band(flags_hi, 0x04) != 0
    tc:      bit.band(flags_hi, 0x02) != 0
    rd:      bit.band(flags_hi, 0x01) != 0
    ra:      bit.band(flags_lo, 0x80) != 0
    rcode:   bit.band(flags_lo, 0x0F)
    qdcount: read_u16 buf, 5
    ancount: read_u16 buf, 7
    nscount: read_u16 buf, 9
    arcount: read_u16 buf, 11
  }

-- ── Décodage des noms DNS avec gestion de la compression ─────────
--
-- RFC 1035 §4.1.4 : un label peut être soit :
--   - une longueur (0-63) suivie d'octets : label ordinaire
--   - 0xC0xx : pointeur de compression (offset depuis le début du message)
--   - 0x00   : fin du nom
--
-- buf    : string Lua du message DNS *complet* (nécessaire pour les pointeurs)
-- offset : position 1-based du début du nom
-- Retourne (name_string, bytes_consumed_in_main_stream)
-- bytes_consumed = octets lus dans le flux principal AVANT tout saut.
decode_name = (buf, offset) ->
  labels   = {}
  pos      = offset
  consumed = 0      -- octets lus dans le flux non-compressé
  jumped   = false  -- a-t-on déjà suivi un pointeur ?
  safety   = 0      -- protection contre les boucles de pointeurs circulaires

  while pos <= #buf
    safety += 1
    return nil, 0 if safety > 64   -- DNS name max 255 chars, 64 labels max

    len = read_u8 buf, pos

    if len == 0
      -- Fin du nom
      consumed += 1 unless jumped
      break

    elseif bit.band(len, 0xC0) == 0xC0
      -- Pointeur de compression : 2 octets, offset 14 bits
      return nil, 0 if pos + 1 > #buf
      high   = bit.band len, 0x3F
      low    = read_u8 buf, pos + 1
      ptr    = bit.bor(bit.lshift(high, 8), low) + 1  -- +1 : 1-based Lua
      consumed += 2 unless jumped
      jumped = true
      pos    = ptr

    else
      -- Label ordinaire : len octets de texte
      label_end = pos + len
      return nil, 0 if label_end > #buf
      table.insert labels, buf\sub(pos + 1, label_end)
      pos      = label_end + 1
      consumed += len + 1 unless jumped

  table.concat(labels, "."), consumed

-- ── Section Questions ─────────────────────────────────────────────
-- Retourne (questions_table, next_offset) ou (nil, nil) si erreur.
-- questions_table : liste de { qname, qtype, qtype_name, qclass, offset_start }
parse_questions = (buf, qdcount) ->
  questions = {}
  pos = 13   -- 1-based : après le header de 12 octets

  for _ = 1, qdcount
    break if pos > #buf

    qname, consumed = decode_name buf, pos
    return nil, nil unless qname

    pos += consumed
    return nil, nil if pos + 3 > #buf

    qtype  = read_u16 buf, pos
    qclass = read_u16 buf, pos + 2
    pos   += 4

    table.insert questions, {
      :qname, :qtype, :qclass
      qtype_name: QTYPE_NAME[qtype] or ("TYPE#{qtype}")
    }

  questions, pos

-- ── Section Answers (Resource Records) ──────────────────────────
-- Retourne la liste des RR de type A et AAAA avec leur TTL et RDATA.
-- Inclut aussi les CNAME pour le log.
-- answers : liste de { name, rtype, rtype_name, ttl, rdata_str, ttl_offset }
--   ttl_offset : position 1-based du champ TTL dans buf (pour patch in-place)
parse_answers = (buf, ancount, start_offset) ->
  answers = {}
  pos     = start_offset

  for _ = 1, ancount
    break if pos > #buf

    -- Nom du RR (souvent un pointeur de compression)
    name, consumed = decode_name buf, pos
    break unless name
    pos += consumed

    break if pos + 9 > #buf   -- type(2) + class(2) + ttl(4) + rdlength(2)

    rtype    = read_u16 buf, pos
    rclass   = read_u16 buf, pos + 2
    ttl      = read_u32 buf, pos + 4
    ttl_offset = pos + 4       -- position 1-based du champ TTL (4 octets)
    rdlength = read_u16 buf, pos + 8
    pos     += 10

    break if pos + rdlength - 1 > #buf

    rdata_str = switch rtype
      when QTYPE.A
        -- 4 octets IPv4
        "#{buf\byte pos}.#{buf\byte pos+1}.#{buf\byte pos+2}.#{buf\byte pos+3}"
      when QTYPE.AAAA
        -- 16 octets IPv6 → notation groupée (non compressée pour simplicité)
        groups = for g = 0, 7
          string.format "%x", read_u16(buf, pos + g*2)
        table.concat groups, ":"
      when QTYPE.CNAME
        cname, _ = decode_name buf, pos
        cname or "?"
      else
        "(rdata #{rdlength}B)"

    table.insert answers, {
      :name, rtype: rtype, rtype_name: QTYPE_NAME[rtype] or "TYPE#{rtype}"
      :ttl, :ttl_offset, :rdlength, :rdata_str, :rclass
      -- Copie brute du RDATA pour extraire les IPs facilement
      rdata_raw: buf\sub(pos, pos + rdlength - 1)
    }

    pos += rdlength

  answers

-- ── Point d'entrée principal ─────────────────────────────────────
-- Analyse un message DNS complet (payload UDP).
-- Retourne nil si le buffer est trop court ou malformé.
parse_dns = (buf) ->
  hdr = parse_header buf
  return nil unless hdr

  questions, ans_offset = parse_questions buf, hdr.qdcount
  return nil unless questions

  answers = {}
  if hdr.is_response and hdr.ancount > 0
    answers = parse_answers buf, hdr.ancount, ans_offset

  { :hdr, :questions, :answers }

-- ── Patch TTL in-place ───────────────────────────────────────────
-- Réécrit le TTL de tous les RR d'une réponse DNS à new_ttl secondes.
-- Travaille sur une copie *mutable* du buffer (ffi uint8_t array).
-- buf_ptr : pointeur ffi uint8_t* (payload DNS mutable, 0-based)
-- answers : table retournée par parse_answers
-- dns_offset : offset 0-based du début DNS dans le paquet IP brut
--              (pour convertir ttl_offset 1-based Lua en index 0-based ffi)
-- new_ttl    : valeur TTL à écrire (uint32)
patch_ttl = (buf_ptr, answers, dns_offset, new_ttl) ->
  for ans in *answers
    -- ttl_offset est 1-based depuis le début du payload DNS
    -- dns_offset est 0-based depuis le début du paquet IP
    -- 0-based dans buf_ptr = dns_offset + (ttl_offset - 1)
    abs_off = dns_offset + ans.ttl_offset - 1
    -- Écriture big-endian du TTL sur 4 octets
    buf_ptr[abs_off]   = bit.rshift(bit.band(new_ttl, 0xFF000000), 24)
    buf_ptr[abs_off+1] = bit.rshift(bit.band(new_ttl, 0x00FF0000), 16)
    buf_ptr[abs_off+2] = bit.rshift(bit.band(new_ttl, 0x0000FF00),  8)
    buf_ptr[abs_off+3] = bit.band(new_ttl, 0x000000FF)

--- Construit le RDATA d'un OPT RR à partir d'un tableau d'options EDNS.
-- Les options dont le code vaut 0 (IANA TBD) sont silencieusement ignorées.
-- @tparam  table options Tableau de tables {code: number, data: string}
-- @treturn string        RDATA binaire
build_opt_rdata = (options) ->
  parts = {}
  for opt in *options
    continue if opt.code == 0   -- option TBD (non encore allouée par IANA)
    data = opt.data
    dlen = #data
    parts[#parts + 1] = string.char(
      bit.rshift(bit.band(opt.code, 0xFF00), 8),
      bit.band(opt.code, 0xFF),
      bit.rshift(bit.band(dlen, 0xFF00), 8),
      bit.band(dlen, 0xFF)) .. data
  table.concat parts

--- Parcourt le nom DNS à la position pos (1-based) et retourne le nombre d'octets consommés.
-- Gère les labels normaux (longueur + contenu) et les pointeurs de compression (2 octets).
-- @tparam string buf DNS payload (Lua string, 1-based)
-- @tparam number pos Position 1-based du début du nom
-- @treturn number    Octets consommés (0 si erreur)
skip_name_bytes = (buf, pos) ->
  len      = #buf
  consumed = 0
  safety   = 0
  while pos <= len
    safety += 1
    return 0 if safety > 128   -- garde contre les boucles de compression
    b = buf\byte pos
    if b == 0
      consumed += 1
      break
    elseif bit.band(b, 0xC0) == 0xC0
      return 0 if pos + 1 > len  -- pointeur tronqué
      consumed += 2
      break
    elseif bit.band(b, 0xC0) != 0x00  -- 0x40 ou 0x80 : types réservés (RFC 1035)
      return 0
    else
      return 0 if pos + b > len  -- label déborde du buffer
      consumed += b + 1
      pos      += b + 1
  consumed

--- Calcule la taille totale d'un RR DNS à la position pos (1-based).
-- Couvre les sections Answer, Authority et Additional.
-- @tparam string buf DNS payload (Lua string, 1-based)
-- @tparam number pos Position 1-based du début du RR
-- @treturn number|nil Octets totaux du RR (nil si paquet trop court)
skip_rr = (buf, pos) ->
  name_bytes = skip_name_bytes buf, pos
  name_end   = pos + name_bytes
  return nil if name_end + 9 > #buf
  rdlength = bit.bor bit.lshift(buf\byte(name_end + 8), 8), buf\byte(name_end + 9)
  name_bytes + 10 + rdlength

--- Injecte une ou plusieurs options EDNS dans la réponse DNS (RFC 6891 §7).
-- Cherche l'OPT RR existant dans la section Additional et y ajoute les options.
-- Ne crée pas d'OPT RR si la réponse n'en a pas (client non-EDNS, RFC 6891).
-- Retourne un nouveau payload DNS Lua-string (pas de mutation in-place).
-- @tparam string dns_payload Payload DNS complet (12+ octets)
-- @tparam table  options     Tableau de tables {code, data} passé à build_opt_rdata
-- @treturn string|nil Nouveau payload DNS, nil si le paquet est invalide ou sans OPT
append_ede_to_dns = (dns_payload, options) ->
  len = #dns_payload
  return nil if len < 12

  qdcount = read_u16 dns_payload, 5
  ancount = read_u16 dns_payload, 7
  nscount = read_u16 dns_payload, 9
  arcount = read_u16 dns_payload, 11

  new_rdata = build_opt_rdata options
  return dns_payload if #new_rdata == 0

  -- Marcher les questions
  pos = 13  -- 1-based, juste après le header de 12 octets
  for _ = 1, qdcount
    nb = skip_name_bytes dns_payload, pos
    return nil if nb == 0
    pos += nb + 4   -- name + QTYPE(2) + QCLASS(2)
    return nil if pos > len + 1  -- dépasse le buffer

  -- Sauter les réponses (Answer + Authority)
  for _ = 1, ancount + nscount
    nb = skip_rr dns_payload, pos
    return nil unless nb
    pos += nb

  -- Chercher l'OPT RR dans la section Additional
  opt_start = nil
  tmp_pos   = pos
  for _ = 1, arcount
    nb = skip_rr dns_payload, tmp_pos
    return nil unless nb
    name_bytes = skip_name_bytes dns_payload, tmp_pos
    return nil if name_bytes == 0 and (dns_payload\byte(tmp_pos) != 0)
    type_pos   = tmp_pos + name_bytes
    return nil if type_pos + 1 > len
    rtype      = read_u16 dns_payload, type_pos
    if rtype == QTYPE_OPT
      opt_start = tmp_pos
      break
    tmp_pos += nb

  -- Pas d'OPT RR : RFC 6891 interdit d'en ajouter un si le client n'en avait pas.
  -- Retourner nil ; l'appelant garde le payload DNS inchangé.
  return nil unless opt_start

  -- OPT RR trouvé : ajouter les options à son RDATA existant
  name_bytes    = skip_name_bytes dns_payload, opt_start
  rdlen_pos     = opt_start + name_bytes + 8  -- après NAME(nb) + TYPE(2) + CLASS(2) + TTL(4)
  return nil if rdlen_pos + 1 > len
  old_rdlen     = read_u16 dns_payload, rdlen_pos
  rdata_start   = rdlen_pos + 2
  rdata_end     = rdata_start + old_rdlen - 1
  return nil if rdata_end > len  -- RDATA déborde du buffer
  new_rdlen     = old_rdlen + #new_rdata
  rdlen_hi      = bit.rshift bit.band(new_rdlen, 0xFF00), 8
  rdlen_lo      = bit.band new_rdlen, 0xFF
  dns_payload\sub(1, rdlen_pos - 1) ..
    string.char(rdlen_hi, rdlen_lo) ..
    dns_payload\sub(rdata_start, rdata_end) ..
    new_rdata ..
    dns_payload\sub(rdata_end + 1)

--- Construit une réponse DNS REFUSED (RCODE 5) avec extension EDNS EDE=15 (Filtered).
-- Copie la section question de la requête originale.
-- @tparam table  dns       Résultat de parse_dns sur la question originale
-- @tparam string orig_buf  Payload DNS brut de la question (UDP payload)
-- @treturn string|nil      Payload UDP DNS de la réponse, nil si construction impossible
build_refused = (dns, orig_buf) ->
  return nil unless dns and orig_buf

  txid    = dns.hdr.txid
  qdcount = dns.hdr.qdcount

  -- ── Header DNS (12 octets) ────────────────────────────────────
  -- flags : QR=1 OPCODE=0 AA=0 TC=0 RD=1 RA=0 RCODE=5 (REFUSED)
  -- ARCOUNT=1 pour l'OPT RR EDNS
  txid_hi = bit.rshift bit.band(txid, 0xFF00), 8
  txid_lo = bit.band txid, 0xFF
  qd_hi   = bit.rshift bit.band(qdcount, 0xFF00), 8
  qd_lo   = bit.band qdcount, 0xFF
  hdr = string.char txid_hi, txid_lo, 0x81, 0x05, qd_hi, qd_lo, 0, 0, 0, 0, 0, 1

  -- ── Section question : copie verbatim de l'original ─────────
  _, ans_offset = parse_questions orig_buf, qdcount
  qs_raw = if ans_offset and ans_offset > 13
    orig_buf\sub 13, ans_offset - 1
  else
    ""

  -- ── RDATA OPT : EDE Filtered + options draft-muks (TBD ignorées) ────
  ede_data = string.char(0x00, EDE_FILTERED) .. EDE_EXTRA_TEXT
  rdata = build_opt_rdata {
    { code: EDNS_OPT_EDE,  data: ede_data }
    { code: EDNS_OPT_LANG, data: FILTER_LANG }   -- TBD → ignoré
    { code: EDNS_OPT_FORG, data: FILTER_ORG  }   -- TBD → ignoré
  }
  rdlen = #rdata

  -- ── EDNS OPT RR (RFC 6891) ───────────────────────────────────
  -- NAME=0x00 (root), TYPE=0x0029, CLASS=0x0500 (1280 oct.), TTL=0
  opt_hdr = string.char(0x00, 0x00, 0x29, 0x05, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        bit.rshift(bit.band(rdlen, 0xFF00), 8),
                        bit.band(rdlen, 0xFF))

  hdr .. qs_raw .. opt_hdr .. rdata

--- Construit une réponse DNS NXDOMAIN (RCODE 3) avec réponse synthétique (0.0.0.0 ou ::) + EDE.
-- Copie la section question de la requête originale et ajoute une réponse A/AAAA synthétique.
-- @tparam table  dns       Résultat de parse_dns sur la question originale
-- @tparam string orig_buf  Payload DNS brut de la question (UDP payload)
-- @treturn string|nil      Payload UDP DNS de la réponse, nil si construction impossible
build_nxdomain = (dns, orig_buf) ->
  return nil unless dns and orig_buf

  txid    = dns.hdr.txid
  qdcount = dns.hdr.qdcount

  -- Déterminer le qtype de la première question
  qtype = if dns.questions and #dns.questions > 0
    dns.questions[1].qtype
  else
    QTYPE.A  -- par défaut

  -- ── Header DNS (12 octets) ────────────────────────────────────
  -- flags : QR=1 OPCODE=0 AA=0 TC=0 RD=1 RA=0 RCODE=3 (NXDOMAIN)
  -- ANCOUNT=1 pour la réponse synthétique, ARCOUNT=1 pour l'OPT RR EDNS
  txid_hi = bit.rshift bit.band(txid, 0xFF00), 8
  txid_lo = bit.band txid, 0xFF
  qd_hi   = bit.rshift bit.band(qdcount, 0xFF00), 8
  qd_lo   = bit.band qdcount, 0xFF
  hdr = string.char txid_hi, txid_lo, 0x81, 0x03, qd_hi, qd_lo, 0, 1, 0, 0, 0, 1

  -- ── Section question : copie verbatim de l'original ─────────
  _, ans_offset = parse_questions orig_buf, qdcount
  qs_raw = if ans_offset and ans_offset > 13
    orig_buf\sub 13, ans_offset - 1
  else
    ""

  -- ── Section réponse : RR synthétique (0.0.0.0 pour A, :: pour AAAA) ──
  -- Utilise un pointeur de compression (0xC0 0x0C) vers le qname de la question
  -- Le qname de la question commence à l'offset 12 (après le header DNS)
  ans_name_ptr = string.char(0xC0, 0x0C)  -- Pointe vers offset 12 (0x0C)

  -- RDATA : 4 octets pour A (0.0.0.0), 16 octets pour AAAA (::)
  rdata = nil
  if qtype == QTYPE.A
    rdata = string.char(0, 0, 0, 0)  -- 0.0.0.0
  elseif qtype == QTYPE.AAAA
    rdata = string.char(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)  -- ::
  else
    rdata = string.char(0, 0, 0, 0)  -- par défaut 0.0.0.0

  rdlen = #rdata

  -- RR answer : NAME=pointer, TYPE=qtype, CLASS=IN (1), TTL=60, RDLEN=rdlen, RDATA
  qtype_hi = bit.rshift bit.band(qtype, 0xFF00), 8
  qtype_lo = bit.band qtype, 0xFF
  ttl_bytes = string.char(
    bit.rshift(bit.band(60, 0xFF000000), 24),
    bit.rshift(bit.band(60, 0x00FF0000), 16),
    bit.rshift(bit.band(60, 0x0000FF00), 8),
    bit.band(60, 0x000000FF)
  )
  rdlen_hi = bit.rshift bit.band(rdlen, 0xFF00), 8
  rdlen_lo = bit.band rdlen, 0xFF

  ans_rr = ans_name_ptr .. string.char(qtype_hi, qtype_lo, 0, 1) .. ttl_bytes .. string.char(rdlen_hi, rdlen_lo) .. rdata

  -- ── RDATA OPT : EDE Filtered + options draft-muks (TBD ignorées) ────
  ede_data = string.char(0x00, EDE_FILTERED) .. EDE_EXTRA_TEXT
  opt_rdata = build_opt_rdata {
    { code: EDNS_OPT_EDE,  data: ede_data }
    { code: EDNS_OPT_LANG, data: FILTER_LANG }   -- TBD → ignoré
    { code: EDNS_OPT_FORG, data: FILTER_ORG  }   -- TBD → ignoré
  }
  opt_rdlen = #opt_rdata

  -- ── EDNS OPT RR (RFC 6891) ───────────────────────────────────
  -- NAME=0x00 (root), TYPE=0x0029, CLASS=0x0500 (1280 oct.), TTL=0
  opt_hdr = string.char(0x00, 0x00, 0x29, 0x05, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        bit.rshift(bit.band(opt_rdlen, 0xFF00), 8),
                        bit.band(opt_rdlen, 0xFF))

  hdr .. qs_raw .. ans_rr .. opt_hdr .. opt_rdata

{ :parse_dns, :parse_header, :parse_questions, :parse_answers
  :decode_name, :patch_ttl, :build_refused, :build_nxdomain
  :build_opt_rdata, :skip_name_bytes, :skip_rr, :append_ede_to_dns
  :QTYPE, :QTYPE_NAME, :QTYPE_OPT, :RCODE
  :EDE_FILTERED, :EDE_EXTRA_TEXT, :EDE_OTHER, :EDE_TTL_TEXT
  :EDNS_OPT_EDE, :EDNS_OPT_LANG, :EDNS_OPT_FORG
  :FILTER_LANG, :FILTER_ORG }
