-- tests/unit/main_chain_strip_spec.moon
{ :chain_strip_active } = require "lib.chain_strip"

describe "chain_strip_active", ->
  it "vrai si une règle a follow_cname", ->
    cfg = { filter: { rules: { { dns_strip: { follow_cname: true } } } } }
    assert.is_true chain_strip_active cfg

  it "faux sinon", ->
    cfg = { filter: { rules: { { dns_strip: { rr_type: "AAAA" } } } } }
    assert.is_false chain_strip_active cfg

  it "faux si pas de rules", ->
    cfg = { filter: {} }
    assert.is_false chain_strip_active cfg

  it "faux si config nil", ->
    assert.is_false chain_strip_active nil
