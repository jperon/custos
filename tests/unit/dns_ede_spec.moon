-- tests/unit/dns_ede_spec.moon
-- Tests unitaires des helpers DNS EDE.

{ :strip_https_rr } = require "dns_ede"
dns_mod = require "ipparse.l7.dns"
pack: sp = require "ipparse.lib.pack_compat"

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
