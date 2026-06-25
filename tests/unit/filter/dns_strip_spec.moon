-- tests/unit/filter/dns_strip_spec.moon
-- Tests de l'action dns_strip, option follow_cname (chain_strip_rr).

package.loaded["ipc"] or= { register_modifier: -> nil }

describe "dns_strip follow_cname", ->
  factory = (require "filter.actions.dns_strip").factory
  dns_mod = require "ipparse.l7.dns"

  it "pose ctx.chain_strip_rr quand follow_cname=true", ->
    act = (factory {}) { dns_strip: { rr_type: "AAAA", follow_cname: true }, description: "x" }
    ctx = { dns_raw: "fake", reason: "r" }
    act.on_response ctx
    assert.are.equal dns_mod.types.AAAA, ctx.chain_strip_rr

  it "ne pose rien sans follow_cname", ->
    act = (factory {}) { dns_strip: { rr_type: "AAAA" }, description: "x" }
    ctx = { dns_raw: "fake", reason: "r" }
    act.on_response ctx
    assert.is_nil ctx.chain_strip_rr
