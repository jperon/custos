-- tests/unit/main_chain_strip_spec.moon
{ :chain_strip_active } = require "lib.chain_strip"

describe "chain_strip_active", ->
  it "vrai si une règle a follow_cname explicite", ->
    cfg = { filter: { rules: { { dns_strip: { follow_cname: true } } } } }
    assert.is_true chain_strip_active cfg

  it "vrai par défaut dès qu'une règle a dns_strip", ->
    cfg = { filter: { rules: { { dns_strip: { rr_type: "AAAA" } } } } }
    assert.is_true chain_strip_active cfg

  it "faux si follow_cname=false (opt-out explicite)", ->
    cfg = { filter: { rules: { { dns_strip: { rr_type: "AAAA", follow_cname: false } } } } }
    assert.is_false chain_strip_active cfg

  it "vrai si dns_strip est une entrée d'action table (forme webui)", ->
    cfg = { filter: { rules: { { actions: { { dns_strip: { rr_type: "AAAA" } }, "allow" } } } } }
    assert.is_true chain_strip_active cfg

  it "faux si dns_strip table a follow_cname=false (opt-out explicite)", ->
    cfg = { filter: { rules: { { actions: { { dns_strip: { rr_type: "AAAA", follow_cname: false } }, "allow" } } } } }
    assert.is_false chain_strip_active cfg

  it "faux si aucune règle dns_strip", ->
    cfg = { filter: { rules: { { description: "x" } } } }
    assert.is_false chain_strip_active cfg

  it "faux si pas de rules", ->
    cfg = { filter: {} }
    assert.is_false chain_strip_active cfg

  it "faux si config nil", ->
    assert.is_false chain_strip_active nil
