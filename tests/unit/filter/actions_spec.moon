-- tests/unit/filter/actions_spec.moon
-- Busted spec pour les actions filter : dns_strip, mail.
-- Charge depuis lua/ (pas de surcharge src/) pour alimenter luacov.

-- Stubs avant tout require de module de production
package.loaded["ipc"] or= { register_modifier: -> nil }

-- dns_ede stub : on contrôle le comportement de strip pour tester on_response
local _dns_ede_stub
_dns_ede_stub = {
  strip_dns_rr: (raw, rtype) ->
    -- Simuler une suppression réelle : retourne une chaîne différente si "A" ou "AAAA"
    if rtype == "A" or rtype == "AAAA"
      raw .. "_stripped"
    else
      raw
  add_ede_modified: (raw, reason) -> raw .. "_ede"
  clear_ad_bit: (raw) -> raw .. "_noad"
}
package.loaded["dns_ede"] = _dns_ede_stub

describe "filter.actions.dns_strip", ->
  dns_strip_factory = require "filter.actions.dns_strip"
  cfg = { nft: { ip_timeout: "2m" } }

  it "strip A : eval retourne true", ->
    rule = { description: "Strip A rule", dns_strip: { rr_type: "A" } }
    action = (dns_strip_factory cfg) rule
    v, msg = action.eval {}
    assert.is_true v
    assert.is_not_nil msg
    assert.match "Strip A", msg

  it "strip AAAA : eval retourne true", ->
    rule = { description: "Strip AAAA rule", dns_strip: { rr_type: "AAAA" } }
    action = (dns_strip_factory cfg) rule
    v, msg = action.eval {}
    assert.is_true v
    assert.match "Strip AAAA", msg

  it "rr_type par défaut = A", ->
    rule = { description: "Default rule" }
    action = (dns_strip_factory cfg) rule
    v, msg = action.eval {}
    assert.is_true v
    assert.match "Strip A", msg

  it "compile_nft retourne nil (pas de support nft)", ->
    rule_cfg = { dns_strip: { rr_type: "A" } }
    rule = { description: "Strip rule" }
    action = (dns_strip_factory cfg, rule_cfg) rule
    stmt = action.compile_nft!
    assert.is_nil stmt

  it "verdict retourne 'accept'", ->
    rule_cfg = { dns_strip: { rr_type: "A" } }
    rule = { description: "Strip rule" }
    action = (dns_strip_factory cfg, rule_cfg) rule
    assert.equals "accept", action.verdict!

  it "capabilities : worker=true, nft=false", ->
    rule_cfg = { dns_strip: { rr_type: "A" } }
    rule = { description: "Strip rule" }
    action = (dns_strip_factory cfg, rule_cfg) rule
    assert.is_true action.capabilities.worker
    assert.is_false action.capabilities.nft

  it "on_response strip A : strip les enregistrements et marque skip_nft", ->
    rule_cfg = { dns_strip: { rr_type: "A" } }
    rule = { description: "Strip A rule" }
    action = (dns_strip_factory cfg, rule_cfg) rule
    ctx = { dns_raw: "original_dns", modified: false, skip_nft: false }
    action.on_response ctx
    assert.is_true ctx.skip_nft
    assert.is_true ctx.modified
    assert.equals "response_strip_A", ctx.action_label

  it "on_response strip AAAA : strip les enregistrements et marque skip_nft", ->
    rule_cfg = { dns_strip: { rr_type: "AAAA" } }
    rule = { description: "Strip AAAA rule" }
    action = (dns_strip_factory cfg, rule_cfg) rule
    ctx = { dns_raw: "original_dns", modified: false, skip_nft: false }
    action.on_response ctx
    assert.is_true ctx.skip_nft
    assert.is_true ctx.modified
    assert.equals "response_strip_AAAA", ctx.action_label

  it "on_response : pas de modification si strip ne change rien", ->
    rule_cfg = { dns_strip: { rr_type: "A" } }
    rule = { description: "Strip A rule" }
    -- Recréer l'action avec un dns_ede qui ne strip rien
    old_stub = package.loaded["dns_ede"]
    package.loaded["dns_ede"] = nil
    package.loaded["filter.actions.dns_strip"] = nil
    package.loaded["dns_ede"] = {
      strip_dns_rr: (raw, _t) -> raw  -- pas de changement
      add_ede_modified: (raw, _r) -> raw
      clear_ad_bit: (raw) -> raw
    }
    local_factory = require "filter.actions.dns_strip"
    local_action = (local_factory cfg) rule
    ctx = { dns_raw: "original_dns", modified: false, skip_nft: false }
    local_action.on_response ctx
    assert.is_true ctx.skip_nft
    assert.is_false ctx.modified
    -- Restaurer
    package.loaded["filter.actions.dns_strip"] = nil
    package.loaded["dns_ede"] = old_stub

describe "filter.actions.mail", ->
  mail_factory = require "filter.actions.mail"
  cfg = { nft: { ip_timeout: "2m" } }
  rule = { description: "Mail rule" }
  action = (mail_factory cfg) rule

  it "retourne nil comme verdict (effet de bord pur)", ->
    v, msg = action {}
    assert.is_nil v
    assert.is_not_nil msg
