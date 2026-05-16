-- tests/unit/dns_ede_spec.moon
-- Tests unitaires des helpers DNS EDE.

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

{ :strip_https_rr, :strip_a_rr, :strip_aaaa_rr, :add_ede_modified, :clear_ad_bit } = require "dns_ede"
dns_mod = require "ipparse.l7.dns"
pack: sp = require "ipparse.lib.pack_compat"
bit = require "bit"

QTYPE_A = dns_mod.types.A
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
