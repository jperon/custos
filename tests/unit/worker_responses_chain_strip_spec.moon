dns_mod = require "ipparse.l7.dns"
sp = require("ipparse.lib.pack_compat").pack
codec = require "strip_codec"

QTYPE_A     = dns_mod.types.A
QTYPE_AAAA  = dns_mod.types.AAAA
QTYPE_CNAME = dns_mod.types.CNAME
QCLASS_IN   = dns_mod.classes.IN

--- Encode un nom DNS en wire (labels len+bytes, terminé par \0). Pas de
-- compression : suffisant pour decode_cname_target / dns_mod.parse.
wire_name = (name) ->
  parts = {}
  for label in name\gmatch "[^.]+"
    parts[#parts + 1] = string.char(#label) .. label
  table.concat(parts) .. "\0"

qname_smtp = wire_name "smtp.office365.com"
qname_target = "atm.outlook.mira.tm.svc.cloud.microsoft"
qname_target_wire = wire_name qname_target

pack_rr = (name_wire, rtype, rdata, ttl=60) ->
  name_wire .. sp(">H H I4 s2", rtype, QCLASS_IN, ttl, rdata)

--- Réponse smtp.office365.com → CNAME atm.outlook... → AAAA (16 octets).
build_chain_resp = ->
  question = qname_smtp .. sp(">H H", QTYPE_A, QCLASS_IN)
  answer_cname = pack_rr qname_smtp, QTYPE_CNAME, qname_target_wire
  aaaa_rdata = string.char(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1)
  answer_aaaa = pack_rr qname_target_wire, QTYPE_AAAA, aaaa_rdata
  header = sp ">H H H H H H", 0x1234, 0x8180, 1, 2, 0, 0
  header .. question .. answer_cname .. answer_aaaa

--- Réponse directe (pas de CNAME) : question == target, un seul RR AAAA.
build_direct_aaaa_resp = ->
  question = qname_target_wire .. sp(">H H", QTYPE_AAAA, QCLASS_IN)
  aaaa_rdata = string.char(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1)
  answer_aaaa = pack_rr qname_target_wire, QTYPE_AAAA, aaaa_rdata
  header = sp ">H H H H H H", 0x1234, 0x8180, 1, 1, 0, 0
  header .. question .. answer_aaaa

fresh_worker_responses = ->
  package.loaded["worker_responses"] = nil
  dofile "lua/worker_responses.lua"

describe "worker_responses chain strip", ->
  before_each ->
    config = require "config"
    config.dns = { ttl_grace: { grace: 0, min: 60, max: 900 } }

  it "record_chain_targets émet un message encodé par cible CNAME", ->
    m = fresh_worker_responses!
    dns_raw = build_chain_resp!
    dns = dns_mod.parse dns_raw, 1, false
    sent = {}
    m.record_chain_targets dns, dns_raw, QTYPE_AAAA, (msg) -> sent[#sent + 1] = msg
    want = codec.encode qname_target, QTYPE_AAAA
    found = false
    for msg in *sent
      found = true if msg == want
    assert.is_true found

  it "record_chain_targets ne fait rien si un argument manque", ->
    m = fresh_worker_responses!
    dns_raw = build_chain_resp!
    dns = dns_mod.parse dns_raw, 1, false
    sent = {}
    m.record_chain_targets nil, dns_raw, QTYPE_AAAA, (msg) -> sent[#sent + 1] = msg
    m.record_chain_targets dns, dns_raw, nil, (msg) -> sent[#sent + 1] = msg
    m.record_chain_targets dns, dns_raw, QTYPE_AAAA, nil
    assert.are.equal 0, #sent

  it "maybe_dynamic_strip strippe quand lookup renvoie un rr_code", ->
    m = fresh_worker_responses!
    dns_raw = build_direct_aaaa_resp!
    out, modified = m.maybe_dynamic_strip qname_target, dns_raw, (-> QTYPE_AAAA)
    assert.is_true modified
    assert.are_not.equal dns_raw, out
    parsed = dns_mod.parse out, 1, false
    n = 0
    for rr in *parsed.answers
      n += 1 if rr.rtype == QTYPE_AAAA
    assert.are.equal 0, n

  it "maybe_dynamic_strip ne touche rien quand lookup renvoie nil", ->
    m = fresh_worker_responses!
    dns_raw = build_direct_aaaa_resp!
    out, modified = m.maybe_dynamic_strip qname_target, dns_raw, (-> nil)
    assert.is_false modified
    assert.are.equal dns_raw, out

  it "maybe_dynamic_strip ne fait rien si un argument manque", ->
    m = fresh_worker_responses!
    dns_raw = build_direct_aaaa_resp!
    out, modified = m.maybe_dynamic_strip nil, dns_raw, (-> QTYPE_AAAA)
    assert.is_false modified
    assert.are.equal dns_raw, out

  it "maybe_dynamic_strip met en cache positif et négatif (borne les appels lookup)", ->
    m = fresh_worker_responses!
    dns_raw = build_direct_aaaa_resp!
    calls = 0
    lookup = ->
      calls += 1
      QTYPE_AAAA
    m.maybe_dynamic_strip qname_target, dns_raw, lookup
    m.maybe_dynamic_strip qname_target, dns_raw, lookup
    assert.are.equal 1, calls

    calls_neg = 0
    lookup_neg = ->
      calls_neg += 1
      nil
    m.maybe_dynamic_strip "legit.example", dns_raw, lookup_neg
    m.maybe_dynamic_strip "legit.example", dns_raw, lookup_neg
    assert.are.equal 1, calls_neg
