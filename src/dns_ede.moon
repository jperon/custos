-- src/dns_ede.moon
-- Shared DNS EDE (RFC 8914) helpers used by worker_responses and doh/query.
--
-- Provides:
--   add_ede(dns, code, text)         -- injects/replaces OPT RR with EDE option
--   build_blocked_response(dns_orig, dns_raw, reason) -- REFUSED + EDE 17
--   add_ede_ttl(dns_payload, reason) -- EDE 4 on TTL-modified allowed responses

dns_mod = require "ipparse.l7.dns"
parse    = dns_mod.parse
REFUSED  = dns_mod.rcodes.REFUSED
A        = dns_mod.types.A
AAAA     = dns_mod.types.AAAA
ede_codes = dns_mod.ede_codes

pack: sp = require "ipparse.lib.pack_compat"

:insert, :remove = table

EDE_BLOCKED     = ede_codes.Filtered       -- 17
EDE_TTL_MODIFIED = ede_codes.Forged_Answer -- 4

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

--- Add EDE code 4 (Forged_Answer / TTL modified) to a raw DNS payload.
-- Returns the original payload unchanged on parse failure.
-- @tparam string     dns_payload Raw DNS payload bytes.
-- @tparam string|nil reason      Human-readable reason for EDE text.
-- @treturn string Modified (or original) DNS payload.
add_ede_ttl = (dns_payload, reason) ->
  dns = parse dns_payload, 1, false
  return dns_payload unless dns

  ede_text = if reason and reason != ""
    "Custos vigilat. " .. reason
  else
    "Custos vigilat."
  add_ede dns, EDE_TTL_MODIFIED, ede_text

  tostring dns

{ :add_ede, :build_blocked_response, :add_ede_ttl, :EDE_BLOCKED, :EDE_TTL_MODIFIED }
