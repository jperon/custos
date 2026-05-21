-- tests/unit/filter/not_spec.moon
-- Tests unitaires pour la méta-condition `not`.

describe "filter.conditions.not", ->
  not_factory = require "filter.conditions.not"
  cfg = { nft: { ip_timeout: "2m" } }

  describe "eval (worker)", ->
    it "négation d'une condition matchée → false", ->
      cond = (not_factory cfg) { from_vlan: 1 }
      ok, msg = cond.eval { vlan: 1 }
      assert.is_false ok
      assert.is_not_nil msg\find "negated to false"

    it "négation d'une condition non-matchée → true", ->
      cond = (not_factory cfg) { from_vlan: 1 }
      ok, msg = cond.eval { vlan: 2 }
      assert.is_true ok
      assert.is_not_nil msg\find "negated to true"

    it "nil pass-through : inner retourne nil → not retourne nil", ->
      -- Injecter un stub de condition qui retourne nil (indéterminé)
      package.loaded["filter.conditions.always_nil"] = (cfg_inner) ->
        (_args) ->
          capabilities: { worker: true, nft: false, nft_dynamic: false }
          eval: (req) -> nil, "indeterminate"
      cond = (not_factory cfg) { always_nil: true }
      ok, msg = cond.eval {}
      assert.is_nil ok
      assert.equals "indeterminate", msg
      package.loaded["filter.conditions.always_nil"] = nil

  describe "capabilities et métadonnées", ->
    it "negate_mark est true", ->
      cond = (not_factory cfg) { from_vlan: 1 }
      assert.is_true cond.negate_mark

    it "capabilities.nft hérite de la sous-condition nft-capable", ->
      cond = (not_factory cfg) { from_vlan: 1 }
      assert.is_true cond.capabilities.nft

    it "capabilities.nft false si sous-condition worker-only", ->
      cond = (not_factory cfg) { in_time: "08:00-18:00" }
      assert.is_false cond.capabilities.nft

    it "capabilities.worker est toujours true", ->
      cond = (not_factory cfg) { from_vlan: 1 }
      assert.is_true cond.capabilities.worker

    it "hérite creates_dynamic_scope si sous-condition le déclare", ->
      cond = (not_factory cfg) { to_domain: "example.com" }
      assert.is_true cond.creates_dynamic_scope

    it "creates_dynamic_scope false si sous-condition ne le déclare pas", ->
      cond = (not_factory cfg) { from_vlan: 1 }
      assert.is_false cond.creates_dynamic_scope

    it "compile_nft délègue à la sous-condition", ->
      cond = (not_factory cfg) { from_vlan: 1 }
      assert.is_function cond.compile_nft
      expr, err = cond.compile_nft "ip"
      assert.is_nil err
      assert.is_not_nil expr\find "vlan", 1, true

  describe "erreurs de configuration", ->
    it "argument non-table → eval retourne false avec message d'erreur", ->
      cond = (not_factory cfg) "pas_une_table"
      ok, msg = cond.eval {}
      assert.is_false ok
      assert.is_not_nil msg\find "requires"

    it "table vide → eval retourne false avec message d'erreur", ->
      cond = (not_factory cfg) {}
      ok, msg = cond.eval {}
      assert.is_false ok
      assert.is_not_nil msg\find "empty"

describe "filter.nft_compiler avec condition not", ->
  compiler = require "filter.nft_compiler"
  rule_mod = require "filter.rule"

  it "génère le pattern deux règles (escape + fallback) pour not: { from_vlan }", ->
    cfg = {
      nft: { ip_timeout: "2m" }
      rules: {
        {
          rule_id: "test_not_vlan"
          actions: {"deny"}
          conditions: {
            not: { from_vlan: 42 }
          }
        }
      }
    }
    compiled = rule_mod.compile_rules cfg
    plan = compiler.compile cfg, compiled.rules_metadata
    out = compiler.render plan

    -- Règle escape : si vlan 42 → return (la condition matchée est sautée)
    assert.is_not_nil out\find "vlan id 42", 1, true
    assert.is_not_nil out\find "not-negation", 1, true

    -- Règle fallback : set mark pour ce qui ne correspond pas à vlan 42
    assert.is_not_nil out\find "counter drop", 1, true

  it "génère escape + fallback avec condition normale combinée", ->
    cfg = {
      nft: { ip_timeout: "2m" }
      rules: {
        {
          rule_id: "test_not_combined"
          actions: {"deny"}
          conditions: {
            from_net: "10.0.0.0/8"
            not: { from_vlan: 42 }
          }
        }
      }
    }
    compiled = rule_mod.compile_rules cfg
    plan = compiler.compile cfg, compiled.rules_metadata
    out = compiler.render plan

    -- Les deux expressions doivent apparaître (net dans escape et fallback)
    assert.is_not_nil out\find "ip saddr", 1, true
    assert.is_not_nil out\find "vlan id 42", 1, true
    assert.is_not_nil out\find "not-negation", 1, true
