-- tests/unit/dns_ede_spec.moon
-- Tests unitaires des helpers DNS EDE.

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

{ :strip_https_rr, :strip_a_rr, :strip_aaaa_rr, :add_ede_modified, :clear_ad_bit, :build_cname_response, :build_sinkhole_response, :build_captive_response } = require "dns_ede"
{ :encode_dns_name } = require "lib.dns_name"
dns_mod = require "ipparse.l7.dns"
{ :s2ip } = require "ipparse.l3.ip"
pack: sp = require "ipparse.lib.pack_compat"
bit = require "bit"

QTYPE_A = dns_mod.types.A
QTYPE_AAAA = dns_mod.types.AAAA
QTYPE_SVCB = dns_mod.types.SVCB
QTYPE_HTTPS = dns_mod.types.HTTPS
QCLASS_IN = dns_mod.classes.IN

qname_example = "\7example\3com\0"
name_ptr = "\192\012" -- compression pointer vers offset 12 (début du qname)

pack_rr = (rtype, rdata, ttl = 60) ->
  name_ptr .. sp(">H H I4 s2", rtype, QCLASS_IN, ttl, rdata)

make_dns_payload = ->
  question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
  answer_a = pack_rr QTYPE_A, string.char(1, 2, 3, 4)
  answer_https = pack_rr QTYPE_HTTPS, "\0\1"
  authority_https = pack_rr QTYPE_HTTPS, "\0\2"
  additional_https = pack_rr QTYPE_HTTPS, "\0\3"
  header = sp(">H H H H H H", 0x1234, 0x8180, 1, 2, 1, 1)
  header .. question .. answer_a .. answer_https .. authority_https .. additional_https

describe "dns_ede.strip_https_rr", ->
  it "retire les RR HTTPS (type 65) et SVCB (type 64) de toutes les sections", ->
    raw = make_dns_payload!
    parsed_before = dns_mod.parse raw, 1, false
    assert.is_not_nil parsed_before
    assert.equals 2, #parsed_before.answers
    assert.equals 1, #parsed_before.authorities
    assert.equals 1, #parsed_before.additionals

    stripped = strip_https_rr raw
    parsed_after = dns_mod.parse stripped, 1, false
    assert.is_not_nil parsed_after
    assert.equals 1, #parsed_after.answers
    assert.equals 0, #parsed_after.authorities
    assert.equals 0, #parsed_after.additionals
    assert.equals QTYPE_A, parsed_after.answers[1].rtype

  it "retire aussi les RR SVCB", ->
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    answer_a = pack_rr QTYPE_A, string.char(1, 1, 1, 1)
    answer_svcb = pack_rr QTYPE_SVCB, "\0\1"
    authority_svcb = pack_rr QTYPE_SVCB, "\0\2"
    additional_svcb = pack_rr QTYPE_SVCB, "\0\3"
    header = sp(">H H H H H H", 0x2345, 0x8180, 1, 2, 1, 1)
    raw = header .. question .. answer_a .. answer_svcb .. authority_svcb .. additional_svcb

    stripped = strip_https_rr raw
    parsed_after = dns_mod.parse stripped, 1, false
    assert.is_not_nil parsed_after
    assert.equals 1, #parsed_after.answers
    assert.equals 0, #parsed_after.authorities
    assert.equals 0, #parsed_after.additionals
    assert.equals QTYPE_A, parsed_after.answers[1].rtype

  it "laisse inchangé un payload sans RR HTTPS", ->
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    answer_a = pack_rr QTYPE_A, string.char(8, 8, 8, 8)
    header = sp(">H H H H H H", 0x4321, 0x8180, 1, 1, 0, 0)
    raw = header .. question .. answer_a
    assert.equals raw, strip_https_rr(raw)

describe "dns_ede.add_ede_modified", ->
  it "ajoute un OPT/EDE code 4 avec texte Custos vigilat", ->
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    answer_a = pack_rr QTYPE_A, string.char(9, 9, 9, 9)
    header = sp(">H H H H H H", 0xBEEF, 0x8180, 1, 1, 0, 0)
    raw = header .. question .. answer_a

    patched = add_ede_modified raw, "policy"
    parsed = dns_mod.parse patched, 1, false
    assert.is_not_nil parsed
    assert.equals 1, #parsed.additionals
    assert.equals 0x29, parsed.additionals[1].rtype
    assert.is_true patched\find("Custos vigilat%. policy", 1) ~= nil

describe "dns_ede.clear_ad_bit", ->
  it "efface le bit AD (0x0020) dans le champ flags", ->
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    answer_a = pack_rr QTYPE_A, string.char(10, 10, 10, 10)
    -- Flags with AD bit set: 0x8520 = 1000 0101 0010 0000 (AD at bit 5 of flags)
    -- QR=1, AA=1, RD=1, RA=1, AD=1
    header = sp(">H H H H H H", 0xBEEF, 0x8520, 1, 1, 0, 0)
    raw = header .. question .. answer_a

    cleared = clear_ad_bit raw
    assert.is_not_nil cleared
    assert.equals raw\byte(1), cleared\byte(1)
    -- Check that AD bit was cleared: 0x8520 & ~0x0020 = 0x8500
    -- Flags field is at bytes 3-4 (1-indexed)
    flags_cleared = cleared\byte(3) * 256 + cleared\byte(4)
    assert.equals 0x8500, flags_cleared

  it "laisse inchangé un payload sans bit AD", ->
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    answer_a = pack_rr QTYPE_A, string.char(11, 11, 11, 11)
    -- Flags without AD bit: 0x8180
    header = sp(">H H H H H H", 0xABCD, 0x8180, 1, 1, 0, 0)
    raw = header .. question .. answer_a

    cleared = clear_ad_bit raw
    assert.equals raw, cleared

describe "dns_ede.strip_a_rr", ->
  it "retire les RR A (IPv4) de la section answers", ->
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    answer_a1 = pack_rr QTYPE_A, string.char(1, 2, 3, 4)
    answer_a2 = pack_rr QTYPE_A, string.char(5, 6, 7, 8)
    header = sp(">H H H H H H", 0x1234, 0x8180, 1, 2, 0, 0)
    raw = header .. question .. answer_a1 .. answer_a2

    stripped = strip_a_rr raw
    parsed_after = dns_mod.parse stripped, 1, false
    assert.is_not_nil parsed_after
    assert.equals 0, #parsed_after.answers

  it "retire seulement les RR A, conserve les autres types", ->
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    answer_a = pack_rr QTYPE_A, string.char(1, 2, 3, 4)
    answer_aaaa = pack_rr dns_mod.types.AAAA, string.char(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1)
    header = sp(">H H H H H H", 0x2345, 0x8180, 1, 2, 0, 0)
    raw = header .. question .. answer_a .. answer_aaaa

    stripped = strip_a_rr raw
    parsed_after = dns_mod.parse stripped, 1, false
    assert.is_not_nil parsed_after
    assert.equals 1, #parsed_after.answers
    assert.equals dns_mod.types.AAAA, parsed_after.answers[1].rtype

  it "laisse inchangé un payload sans RR A", ->
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    answer_aaaa = pack_rr dns_mod.types.AAAA, string.char(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1)
    header = sp(">H H H H H H", 0x4321, 0x8180, 1, 1, 0, 0)
    raw = header .. question .. answer_aaaa
    assert.equals raw, strip_a_rr(raw)

describe "dns_ede.strip_aaaa_rr", ->
  it "retire les RR AAAA (IPv6) de la section answers", ->
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    answer_aaaa1 = pack_rr dns_mod.types.AAAA, string.char(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1)
    answer_aaaa2 = pack_rr dns_mod.types.AAAA, string.char(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2)
    header = sp(">H H H H H H", 0x1234, 0x8180, 1, 2, 0, 0)
    raw = header .. question .. answer_aaaa1 .. answer_aaaa2

    stripped = strip_aaaa_rr raw
    parsed_after = dns_mod.parse stripped, 1, false
    assert.is_not_nil parsed_after
    assert.equals 0, #parsed_after.answers

  it "retire seulement les RR AAAA, conserve les autres types", ->
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    answer_a = pack_rr QTYPE_A, string.char(1, 2, 3, 4)
    answer_aaaa = pack_rr dns_mod.types.AAAA, string.char(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1)
    header = sp(">H H H H H H", 0x2345, 0x8180, 1, 2, 0, 0)
    raw = header .. question .. answer_a .. answer_aaaa

    stripped = strip_aaaa_rr raw
    parsed_after = dns_mod.parse stripped, 1, false
    assert.is_not_nil parsed_after
    assert.equals 1, #parsed_after.answers
    assert.equals QTYPE_A, parsed_after.answers[1].rtype

  it "laisse inchangé un payload sans RR AAAA", ->
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    answer_a = pack_rr QTYPE_A, string.char(1, 2, 3, 4)
    header = sp(">H H H H H H", 0x4321, 0x8180, 1, 1, 0, 0)
    raw = header .. question .. answer_a
    assert.equals raw, strip_aaaa_rr(raw)

describe "build_cname_response", ->
  CNAME = dns_mod.types.CNAME
  get_rcode = (raw) -> bit.band raw\byte(4), 0x0f
  decode_name = (rdata) ->
    labels, i = {}, 1
    while i <= #rdata
      l = rdata\byte i
      break if l == 0
      labels[#labels + 1] = rdata\sub i + 1, i + l
      i += l + 1
    table.concat labels, "."

  make_query = (qtype = QTYPE_A) ->
    q = dns_mod.new {
      header: dns_mod.new_header id: 0x1234, rd: true
      questions: {{ qname: encode_dns_name("www.google.com"), qtype: qtype, qclass: QCLASS_IN }}
    }
    "#{q}"

  it "produit une réponse NOERROR avec un unique RR CNAME vers la cible", ->
    resp = build_cname_response nil, make_query!, "forcesafesearch.google.com", "SafeSearch"
    assert.is_not_nil resp
    assert.equals 0, get_rcode resp
    parsed = dns_mod.parse resp, 1, false
    assert.equals 1, parsed.header.ancount
    assert.equals CNAME, parsed.answers[1].rtype
    assert.equals "forcesafesearch.google.com", decode_name parsed.answers[1].rdata

  it "fonctionne quel que soit le qtype de la question (ex: AAAA)", ->
    resp = build_cname_response nil, make_query(dns_mod.types.AAAA), "restrict.youtube.com", nil
    parsed = dns_mod.parse resp, 1, false
    assert.equals CNAME, parsed.answers[1].rtype

  it "peut enrichir avec des A/AAAA résolus pour la cible", ->
    rrset = {
      a: { s2ip "203.0.113.10" }
      aaaa: { s2ip "2001:db8::10" }
      ttl: 120
    }
    resp = build_cname_response nil, make_query!, "forcesafesearch.google.com", "SafeSearch", rrset
    parsed = dns_mod.parse resp, 1, false
    assert.equals 3, parsed.header.ancount
    assert.equals CNAME, parsed.answers[1].rtype
    assert.equals QTYPE_A, parsed.answers[2].rtype
    assert.equals QTYPE_AAAA, parsed.answers[3].rtype
    assert.equals 120, parsed.answers[2].ttl
    assert.equals 120, parsed.answers[3].ttl

  it "renvoie nil si dns_raw absent ou cible vide", ->
    assert.is_nil build_cname_response nil, nil, "x.example", nil
    assert.is_nil build_cname_response nil, make_query!, "", nil

  it "marque la réponse d'une EDE (OPT RR présent dans additionals)", ->
    resp = build_cname_response nil, make_query!, "safe.duckduckgo.com", "x"
    parsed = dns_mod.parse resp, 1, false
    has_opt = false
    for rr in *(parsed.additionals or {})
      has_opt = true if rr.rtype == 0x29
    assert.is_true has_opt

describe "build_sinkhole_response", ->
  get_rcode = (raw) -> bit.band raw\byte(4), 0x0f
  make_query = (qtype = QTYPE_A) ->
    q = dns_mod.new {
      header: dns_mod.new_header id: 0x1234, rd: true
      questions: {{ qname: encode_dns_name("blocked.example.com"), qtype: qtype, qclass: QCLASS_IN }}
    }
    "#{q}"

  it "reproduit A 0.0.0.0 en NOERROR avec EDE", ->
    sink = { a: { string.rep("\0", 4) }, aaaa: {}, ttl: 30 }
    resp = build_sinkhole_response {}, make_query!, "Filtered by upstream validator", sink
    assert.is_not_nil resp
    assert.equals 0, get_rcode resp          -- NOERROR, pas NXDOMAIN
    parsed = dns_mod.parse resp, 1, false
    assert.equals 1, parsed.header.ancount
    assert.equals QTYPE_A, parsed.answers[1].rtype
    assert.equals string.rep("\0", 4), parsed.answers[1].rdata
    assert.equals 30, parsed.answers[1].ttl
    has_opt = false
    for rr in *(parsed.additionals or {})
      has_opt = true if rr.rtype == 0x29
    assert.is_true has_opt

  it "reproduit AAAA :: ", ->
    sink = { a: {}, aaaa: { string.rep("\0", 16) }, ttl: 60 }
    resp = build_sinkhole_response {}, make_query(dns_mod.types.AAAA), nil, sink
    parsed = dns_mod.parse resp, 1, false
    assert.equals QTYPE_AAAA, parsed.answers[1].rtype
    assert.equals string.rep("\0", 16), parsed.answers[1].rdata

  it "renvoie nil si dns_orig ou dns_raw absent", ->
    assert.is_nil build_sinkhole_response nil, make_query!, "x", { a: {} }
    assert.is_nil build_sinkhole_response {}, nil, "x", { a: {} }

describe "build_captive_response", ->
  get_rcode = (raw) -> bit.band raw\byte(4), 0x0f
  aa_set    = (raw) -> bit.band(raw\byte(3), 0x04) != 0
  make_query = (qtype = QTYPE_A) ->
    q = dns_mod.new {
      header: dns_mod.new_header id: 0x1234, rd: true
      questions: {{ qname: encode_dns_name("captive.lan"), qtype: qtype, qclass: QCLASS_IN }}
    }
    "#{q}"

  it "question A → A locale, NOERROR, AA, TTL 0", ->
    resp = build_captive_response nil, make_query!, "10.35.1.254", "fd00::1"
    assert.is_not_nil resp
    assert.equals 0, get_rcode resp
    assert.is_true aa_set resp
    parsed = dns_mod.parse resp, 1, false
    assert.equals 1, parsed.header.ancount
    assert.equals QTYPE_A, parsed.answers[1].rtype
    assert.equals s2ip("10.35.1.254"), parsed.answers[1].rdata
    assert.equals 0, parsed.answers[1].ttl

  it "question AAAA → AAAA locale", ->
    resp = build_captive_response nil, make_query(QTYPE_AAAA), "10.35.1.254", "fd00::1"
    parsed = dns_mod.parse resp, 1, false
    assert.equals 1, parsed.header.ancount
    assert.equals QTYPE_AAAA, parsed.answers[1].rtype
    assert.equals s2ip("fd00::1"), parsed.answers[1].rdata

  it "famille demandée absente → NOERROR ancount 0", ->
    resp = build_captive_response nil, make_query(QTYPE_AAAA), "10.35.1.254", nil
    assert.is_not_nil resp
    assert.equals 0, get_rcode resp
    parsed = dns_mod.parse resp, 1, false
    assert.equals 0, parsed.header.ancount

  it "renvoie nil si dns_raw absent", ->
    assert.is_nil build_captive_response nil, nil, "10.35.1.254", nil
