-- tests/unit/filter/nxdomain_action_spec.moon
-- Tests de l'action nxdomain et de build_nxdomain_response.

package.loaded["ipc"] or= { register_modifier: -> nil }

describe "filter.actions.nxdomain", ->
  nxdomain_factory = (require "filter.actions.nxdomain").factory
  cfg = {}

  it "eval retourne false (blocage)", ->
    action = (nxdomain_factory cfg) { description: "Canary" }
    v, msg = action.eval {}
    assert.is_false v
    assert.match "Canary", msg

  it "block_modifiers contient nxdomain=true", ->
    action = (nxdomain_factory cfg) { description: "Test" }
    assert.not_nil action.block_modifiers
    assert.is_true action.block_modifiers.nxdomain

  it "capabilities.worker=true et nft=true", ->
    action = (nxdomain_factory cfg) { description: "Test" }
    assert.is_true action.capabilities.worker
    assert.is_true action.capabilities.nft

describe "dns_ede.build_nxdomain_response", ->
  { :build_nxdomain_response, :build_blocked_response } = require "dns_ede"
  { parse: parse_dns } = require "ipparse.l7.dns"
  bit = require "bit"
  -- Le getter header.rcode est booléen ; le rcode numérique est dans octet 4.
  get_rcode = (raw) -> bit.band raw\byte(4), 0x0f

  -- Construit un paquet DNS de question minimal pour A qname=test.local
  make_query = ->
    -- DNS header + question "test.local" A
    -- id=0x1234, flags=0x0100 (RD), qdcount=1
    -- qname=\x04test\x05local\x00, qtype=1(A), qclass=1
    header = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname  = "\x04test\x05local\x00"
    qtype  = "\x00\x01"
    qclass = "\x00\x01"
    header .. qname .. qtype .. qclass

  it "retourne un payload DNS non-nil", ->
    raw = make_query!
    dns, _ = parse_dns raw, 1, false
    result = build_nxdomain_response dns, raw, "Test reason"
    assert.not_nil result
    assert.truthy #result > 0

  it "rcode est NXDOMAIN (3)", ->
    raw = make_query!
    dns, _ = parse_dns raw, 1, false
    result = build_nxdomain_response dns, raw, "Test reason"
    assert.not_nil result
    assert.equals 3, get_rcode result

  it "pas d'enregistrement A synthétique (ancount=0)", ->
    raw = make_query!
    dns, _ = parse_dns raw, 1, false
    result = build_nxdomain_response dns, raw, "Test reason"
    assert.not_nil result
    parsed, _ = parse_dns result, 1, false
    assert.not_nil parsed
    assert.equals 0, #(parsed.answers or {})

  it "rcode de build_blocked_response est REFUSED (5), pas NXDOMAIN", ->
    raw = make_query!
    dns, _ = parse_dns raw, 1, false
    result = build_blocked_response dns, raw, "Test"
    assert.not_nil result
    assert.equals 5, get_rcode result
