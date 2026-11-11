-- tests/unit/lib/filter_data_spec.moon
{ :build_filter_data } = require "lib.filter_data"

describe "build_filter_data", ->
  fake_filter = ->
    rules_obj = { rules_metadata: {} }
    {
      get_rules: -> rules_obj
      auth_cfg_cache: { redirect_url: "https://portal/" }
      sni_cfg_cache: { mode: "permissive", protocols: "tls1.2" }
      decision_cfg: { default_action: "block" }
    }

  it "produit toutes les clés attendues par les workers", ->
    data = build_filter_data fake_filter!
    assert.same { rules_metadata: {} }, data.rules
    assert.same { redirect_url: "https://portal/" }, data.auth_cfg_cache
    assert.same { default_action: "block" }, data.decision_cfg

  it "inclut sni_cfg_cache (politique SNI perdue après SIGHUP si absent)", ->
    data = build_filter_data fake_filter!
    assert.same { mode: "permissive", protocols: "tls1.2" }, data.sni_cfg_cache

  it "appelle get_rules à chaque construction (règles rechargées)", ->
    filter = fake_filter!
    calls = 0
    filter.get_rules = ->
      calls += 1
      { rules_metadata: { calls: calls } }
    data = build_filter_data filter
    assert.equal 1, calls
    assert.same { rules_metadata: { calls: 1 } }, data.rules
