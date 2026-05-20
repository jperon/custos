-- src/dns_ede.moon
-- Shared DNS EDE (RFC 8914) helpers used by worker_responses and doh/query.
--
-- Provides:
--   add_ede(dns, code, text)         -- injects/replaces OPT RR with EDE option
--   build_blocked_response(dns_orig, dns_raw, reason) -- REFUSED + EDE 17
--   add_ede_modified(dns_payload, reason) -- EDE 4 on modified allowed/dnsonly responses
--   strip_https_rr(dns_payload)      -- removes HTTPS/SVCB RRs from all sections

dns_mod = require "ipparse.l7.dns"
parse    = dns_mod.parse
REFUSED  = dns_mod.rcodes.REFUSED
A        = dns_mod.types.A
AAAA     = dns_mod.types.AAAA
HTTPS    = dns_mod.types.HTTPS
SVCB     = dns_mod.types.SVCB
ede_codes = dns_mod.ede_codes

pack: sp = require "ipparse.lib.pack_compat"
bit = require "bit"

:insert, :remove = table

EDE_BLOCKED     = ede_codes.Filtered       -- 17
EDE_TTL_MODIFIED = ede_codes.Forged_Answer -- 4

-- DNS header flags bit masks (RFC 1035)
DNS_FLAG_AD = 0x0020  -- Authenticated Data bit (bit 5)

--- Add or replace the EDNS OPT RR carrying an EDE option in a parsed DNS message.
-- Removes any existing OPT RR (rtype 0x29) then prepends a new one.
-- @tparam table  dns  Parsed DNS message (mutated in-place).
-- @tparam number code EDE info-code (RFC 8914).
-- @tparam string text Extra text for the EDE option.
-- @treturn table dns (the same table, mutated)
add_ede = (dns, code, text) ->
  for i = #(dns.additionals or {}), 1, -1
    if dns.additionals[i].rtype == 0x29
      remove dns.additionals, i

  dns.additionals or= {}
  insert dns.additionals, 1, {
    rname:  "\0"
    rtype:  0x29
    rclass: 0
    ttl:    0
    rdata:  sp ">Hs2", 0x000F, (sp(">H", code) .. text)
  }
  dns.header.arcount = #dns.additionals
  dns

--- Build a REFUSED DNS response with EDE code 17 (Filtered).
-- Returns the packed DNS binary string, or nil on parse failure.
-- @tparam table       dns_orig Parsed question packet's dns table (for qtype).
-- @tparam string      dns_raw  Raw DNS payload bytes extracted from the packet.
-- @tparam string|nil  reason   Human-readable block reason for EDE text.
-- @treturn string|nil Packed DNS response, or nil.
build_blocked_response = (dns_orig, dns_raw, reason) ->
  return nil unless dns_orig and dns_raw

  dns = parse dns_raw, 1, false
  return nil unless dns

  dns.header.rcode = REFUSED
  dns.answers = {}

  if dns.question and dns.question.qtype
    qtype = dns.question.qtype
    rdata = if qtype == A
      string.char 0, 0, 0, 0
    elseif qtype == AAAA
      string.char 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    else
      string.char 0, 0, 0, 0

    dns.answers[1] = {
      rname:  string.char 0xC0, 0x0C
      rtype:  qtype
      rclass: 1
      ttl:    60
      rdata:  rdata
    }
    dns.header.ancount = 1

  ede_text = if reason and reason != ""
    "Ne intretis. " .. reason
  else
    "Ne intretis."
  add_ede dns, EDE_BLOCKED, ede_text

  tostring dns

--- Add EDE code 4 (Forged_Answer / modified answer) to a raw DNS payload.
-- Returns the original payload unchanged on parse failure.
-- @tparam string     dns_payload Raw DNS payload bytes.
-- @tparam string|nil reason      Human-readable reason for EDE text.
-- @treturn string Modified (or original) DNS payload.
add_ede_modified = (dns_payload, reason) ->
  dns = parse dns_payload, 1, false
  return dns_payload unless dns

  ede_text = if reason and reason != ""
    "Custos vigilat. " .. reason
  else
    "Custos vigilat."
  add_ede dns, EDE_TTL_MODIFIED, ede_text

  tostring dns

strip_rrtypes = (dns_payload, rrtypes) ->
  return dns_payload unless dns_payload and #dns_payload >= 12

  len = #dns_payload
  u16 = (off) ->
    return nil if off + 1 > len
    dns_payload\byte(off) * 256 + dns_payload\byte(off + 1)

  skip_name = (off) ->
    cur = off
    steps = 0
    while cur <= len
      steps += 1
      return nil if steps > 128
      b = dns_payload\byte cur
      return nil unless b
      if b == 0
        return cur + 1
      elseif b >= 0xC0
        return nil if cur + 1 > len
        return cur + 2
      else
        return nil if cur + b > len
        cur += 1 + b

    nil

  id = u16 1
  flags = u16 3
  qdcount = u16 5
  ancount = u16 7
  nscount = u16 9
  arcount = u16 11
  return dns_payload unless id and flags and qdcount and ancount and nscount and arcount

  off = 13
  question_parts = {}
  for i = 1, qdcount
    q_end = skip_name off
    return dns_payload unless q_end
    return dns_payload if q_end + 3 > len
    question_parts[#question_parts + 1] = dns_payload\sub off, q_end + 3
    off = q_end + 4

  copy_section = (count) ->
    kept = 0
    sec = {}
    for i = 1, count
      rr_start = off
      name_end = skip_name off
      return nil unless name_end
      return nil if name_end + 9 > len

      rrtype = u16(name_end)
      rdlength = u16(name_end + 8)
      rr_end = name_end + 10 + rdlength - 1
      return nil if rr_end > len

      if not rrtypes[rrtype]
        sec[#sec + 1] = dns_payload\sub rr_start, rr_end
        kept += 1

      off = rr_end + 1

    kept, table.concat sec

  ancount_new, answers = copy_section ancount
  return dns_payload unless answers
  nscount_new, authorities = copy_section nscount
  return dns_payload unless authorities
  arcount_new, additionals = copy_section arcount
  return dns_payload unless additionals

  header = sp ">H H H H H H", id, flags, qdcount, ancount_new, nscount_new, arcount_new
  header .. table.concat(question_parts) .. answers .. authorities .. additionals

--- Supprime les RR d'un ou plusieurs types DNS d'un payload brut.
-- @tparam  string         dns_payload Payload DNS brut.
-- @tparam  number|string|table rtype  Type DNS : entier (ex: 28), nom (ex: "AAAA"),
--                                     ou table de tels éléments (ex: {"HTTPS","SVCB"}).
-- @treturn string Payload modifié, ou original si rien à supprimer / erreur de parse.
strip_dns_rr = (dns_payload, rtype) ->
  resolve = (t) ->
    return t if type(t) == "number"
    v = dns_mod.types[t]
    error "strip_dns_rr : type DNS inconnu '#{t}'" unless v
    v
  set = {}
  if type(rtype) == "table"
    for t in *rtype
      set[resolve(t)] = true
  else
    set[resolve(rtype)] = true
  strip_rrtypes dns_payload, set

-- Aliases spécialisés — définis en termes de strip_dns_rr.
strip_a_rr     = (p) -> strip_dns_rr p, A
strip_aaaa_rr  = (p) -> strip_dns_rr p, AAAA
strip_https_rr = (p) -> strip_dns_rr p, { HTTPS, SVCB }

--- Clear the AD (Authenticated Data) bit in a DNS response.
-- This is used when HTTPS/SVCB records are stripped, as the signature
-- becomes invalid and the response is no longer authenticated.
-- @tparam string dns_payload Raw DNS payload bytes.
-- @treturn string Modified DNS payload with AD bit cleared (or original if invalid).
clear_ad_bit = (dns_payload) ->
  return dns_payload unless dns_payload and #dns_payload >= 4
  
  -- Flags field is at offset 3-4 (1-indexed; big-endian 16-bit value)
  -- DNS header: bytes 1-2=ID, bytes 3-4=FLAGS, bytes 5-6=QDCOUNT, etc.
  flags = dns_payload\byte(3) * 256 + dns_payload\byte(4)
  
  -- Clear AD bit (0x0020)
  flags_new = bit.band(flags, bit.bnot(DNS_FLAG_AD))
  
  -- If flags unchanged, return original
  return dns_payload if flags_new == flags
  
  -- Reconstruct DNS payload with cleared AD bit
  dns_payload\sub(1, 2) .. string.char(bit.rshift(flags_new, 8)) .. string.char(bit.band(flags_new, 0xFF)) .. dns_payload\sub(5)

{ :add_ede, :build_blocked_response, :add_ede_modified, :strip_dns_rr, :strip_https_rr, :strip_a_rr, :strip_aaaa_rr, :clear_ad_bit, :EDE_BLOCKED, :EDE_TTL_MODIFIED }
