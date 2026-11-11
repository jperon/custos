-- tests/unit/nft_add_helper_spec.moon
-- Spec direct de src/nft_add_helper.moon : politique de retry/backoff.
-- config.nft.add_backoff_ms est mis à {0,0,…} pour ne pas dormir réellement ;
-- la longueur du tableau détermine le nombre de tentatives.

config = require "config"
nft_add_helper = require "nft_add_helper"

orig_backoffs = config.nft.add_backoff_ms

describe "nft_add_helper.try_add_with_retries", ->
  before_each ->
    config.nft.add_backoff_ms = { 0, 0, 0 }

  after_each ->
    config.nft.add_backoff_ms = orig_backoffs

  it "succès immédiat → true et un seul appel", ->
    calls = 0
    ok = nft_add_helper.try_add_with_retries ->
      calls += 1
      true, nil
    assert.is_true ok
    assert.equals 1, calls

  it "réessaie jusqu'au succès et transmet les arguments", ->
    calls = 0
    seen = {}
    fn = (client, dest) ->
      calls += 1
      seen[#seen + 1] = "#{client}>#{dest}"
      calls >= 3, "busy"
    ok = nft_add_helper.try_add_with_retries fn, "10.0.0.5", "1.2.3.4"
    assert.is_true ok
    assert.equals 3, calls
    assert.same { "10.0.0.5>1.2.3.4", "10.0.0.5>1.2.3.4", "10.0.0.5>1.2.3.4" }, seen

  it "toutes les tentatives échouent → false, exactement #backoffs appels", ->
    calls = 0
    ok = nft_add_helper.try_add_with_retries ->
      calls += 1
      false, "nft busy"
    assert.is_false ok
    assert.equals 3, calls

  it "la longueur du tableau fixe le nombre de tentatives", ->
    config.nft.add_backoff_ms = { 0 }
    calls = 0
    ok = nft_add_helper.try_add_with_retries ->
      calls += 1
      false, "nft busy"
    assert.is_false ok
    assert.equals 1, calls

  it "un retour falsy sans erreur est traité comme un échec", ->
    calls = 0
    ok = nft_add_helper.try_add_with_retries ->
      calls += 1
      nil, nil
    assert.is_false ok
    assert.equals 3, calls

-- ── Log d'épuisement : la dernière erreur doit être conservée ────────────
-- `last_err` était assignée dans la boucle (donc locale à celle-ci) et lue
-- après : la lecture compilait en globale (nil) et le log perdait toujours
-- l'erreur de la dernière tentative.

-- Recharge le module avec un `log` stub pour capturer les champs loggés.
-- Le module capture log_warn à son chargement ; package.loaded est restauré
-- aussitôt après pour ne pas affecter les autres specs du même processus.
reload_with_log_stub = ->
  saved_log    = package.loaded["log"]
  saved_helper = package.loaded["nft_add_helper"]
  captured = {}
  package.loaded["log"] = {
    log_warn: (thunk) -> captured[#captured + 1] = thunk!
  }
  package.loaded["nft_add_helper"] = nil
  helper = require "nft_add_helper"
  package.loaded["log"]    = saved_log
  package.loaded["nft_add_helper"] = saved_helper
  helper, captured

describe "nft_add_helper.try_add_with_retries log d'épuisement", ->
  before_each ->
    config.nft.add_backoff_ms = { 0 }

  after_each ->
    config.nft.add_backoff_ms = orig_backoffs

  it "conserve la dernière erreur dans nft_add_retries_exhausted", ->
    helper, captured = reload_with_log_stub!
    ok = helper.try_add_with_retries -> false, "nft busy"
    assert.is_false ok
    assert.equals 1, #captured
    assert.equals "nft_add_retries_exhausted", captured[1].action
    assert.equals "nft busy", captured[1].err
