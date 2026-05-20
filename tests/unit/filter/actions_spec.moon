-- tests/unit/filter/actions_spec.moon
-- Busted spec pour les actions filter : strip_A, strip_AAAA, mail.
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

describe "filter.actions.strip_A", ->
  strip_A_factory = require "filter.actions.strip_A"
  cfg = { nft: { ip_timeout: "2m" } }
  rule = { description: "Strip A rule" }

  action = (strip_A_factory cfg) rule

  it "eval retourne true (verdict allow)", ->
    v, msg = action.eval {}
    assert.is_true v
    assert.is_not_nil msg

  it "compile_nft retourne nil (pas de support nft)", ->
    stmt = action.compile_nft!
    assert.is_nil stmt

  it "verdict retourne 'accept'", ->
    assert.equals "accept", action.verdict!

  it "capabilities : worker=true, nft=false", ->
    assert.is_true action.capabilities.worker
    assert.is_false action.capabilities.nft

  it "on_response : strip les enregistrements A et marque skip_nft", ->
    ctx = { dns_raw: "original_dns", modified: false, skip_nft: false }
    action.on_response ctx
    assert.is_true ctx.skip_nft
    -- Le contenu DNS a changé → modified=true et champs enrichis
    assert.is_true ctx.modified
    assert.equals "response_strip_a", ctx.action_label

  it "on_response : pas de modification si strip ne change rien", ->
    -- Recréer l'action avec un dns_ede qui ne strip rien
    old_stub = package.loaded["dns_ede"]
    package.loaded["dns_ede"] = nil
    package.loaded["filter.actions.strip_A"] = nil  -- forcer rechargement
    package.loaded["dns_ede"] = {
      strip_dns_rr: (raw, _t) -> raw  -- pas de changement
      add_ede_modified: (raw, _r) -> raw
      clear_ad_bit: (raw) -> raw
    }
    local_factory = require "filter.actions.strip_A"
    local_action = (local_factory cfg) rule
    ctx = { dns_raw: "original_dns", modified: false, skip_nft: false }
    local_action.on_response ctx
    assert.is_true ctx.skip_nft    -- skip_nft toujours posé
    assert.is_false ctx.modified   -- pas modifié
    -- Restaurer
    package.loaded["filter.actions.strip_A"] = nil
    package.loaded["dns_ede"] = old_stub

describe "filter.actions.strip_AAAA", ->
  -- Recharger avec le stub dns_ede original
  package.loaded["filter.actions.strip_AAAA"] = nil
  strip_AAAA_factory = require "filter.actions.strip_AAAA"
  cfg = { nft: { ip_timeout: "2m" } }
  rule = { description: "Strip AAAA rule" }
  action = (strip_AAAA_factory cfg) rule

  it "eval retourne true", ->
    v, _ = action.eval {}
    assert.is_true v

  it "compile_nft retourne nil", ->
    assert.is_nil action.compile_nft!

  it "verdict retourne 'accept'", ->
    assert.equals "accept", action.verdict!

  it "capabilities : worker=true, nft=false", ->
    assert.is_true action.capabilities.worker
    assert.is_false action.capabilities.nft

  it "on_response : strip les AAAA et marque skip_nft + modified", ->
    ctx = { dns_raw: "original_dns", modified: false, skip_nft: false }
    action.on_response ctx
    assert.is_true ctx.skip_nft
    assert.is_true ctx.modified
    assert.equals "response_strip_aaaa", ctx.action_label

describe "filter.actions.mail", ->
  mail_factory = require "filter.actions.mail"
  cfg = { nft: { ip_timeout: "2m" } }
  rule = { description: "Mail rule" }
  action = (mail_factory cfg) rule

  it "retourne nil comme verdict (effet de bord pur)", ->
    v, msg = action {}
    assert.is_nil v
    assert.is_not_nil msg
