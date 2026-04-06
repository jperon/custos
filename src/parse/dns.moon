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

-- Code EDE « Filtered » (RFC 8914 §5.16)
EDE_FILTERED = 15

-- Message additionnel EDE (RFC 8914 §4, champ extra-text UTF-8 après l'info-code)
EDE_EXTRA_TEXT = "Ne intretis."

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
  -- parse_questions retourne (questions, next_offset) ; next_offset est
  -- la position 1-based du premier octet APRÈS la section questions.
  _, ans_offset = parse_questions orig_buf, qdcount
  qs_raw = if ans_offset and ans_offset > 13
    orig_buf\sub 13, ans_offset - 1
  else
    ""

  -- ── EDNS OPT RR (RFC 6891) avec option EDE=15 (RFC 8914) ─────
  -- NAME=0x00 (root), TYPE=0x0029 OPT, CLASS=0x0500 (1280 octets),
  -- TTL=0x00000000,
  -- RDATA : OPTION-CODE=0x000F EDE, OPTION-LEN=2+N, INFO-CODE=0x000F Filtered,
  --         EXTRA-TEXT = EDE_EXTRA_TEXT (N octets UTF-8, RFC 8914 §4)
  -- RDLENGTH = 6 + N
  ede_n   = #EDE_EXTRA_TEXT
  rdlen   = 6 + ede_n
  opt_len = 2 + ede_n
  -- En-tête OPT RR : NAME(1) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
  opt_hdr = string.char(0x00, 0x00, 0x29, 0x05, 0x00,
                        0x00, 0x00, 0x00, 0x00,
                        bit.rshift(bit.band(rdlen, 0xFF00), 8),
                        bit.band(rdlen, 0xFF))
  -- RDATA EDE : OPTION-CODE(2) + OPTION-LEN(2) + INFO-CODE(2)
  opt_ede = string.char(0x00, 0x0F,
                        bit.rshift(bit.band(opt_len, 0xFF00), 8),
                        bit.band(opt_len, 0xFF),
                        0x00, 0x0F)
  opt_rr = opt_hdr .. opt_ede .. EDE_EXTRA_TEXT

  hdr .. qs_raw .. opt_rr

{ :parse_dns, :parse_header, :parse_questions, :parse_answers
  :decode_name, :patch_ttl, :build_refused
  :QTYPE, :QTYPE_NAME, :RCODE, :EDE_FILTERED, :EDE_EXTRA_TEXT }
