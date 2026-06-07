-- tests/unit/log_spec.moon
-- Couvre log.level_enabled (garde de niveau du hot path).
--
-- busted_setup stubbe `log` globalement ; on charge ici le VRAI module en
-- injectant un config minimal (runtime.log_level), puis on restaure les stubs
-- pour ne pas contaminer les specs suivantes.

describe "log", ->
  local log, saved_log, saved_config

  setup ->
    saved_log    = package.loaded["log"]
    saved_config = package.loaded["config"]
    package.loaded["log"] = nil
    package.loaded["config"] = { runtime: { log_level: "INFO" } }
    log = require "log"

  teardown ->
    package.loaded["log"]    = saved_log
    package.loaded["config"] = saved_config

  it "niveau sous le seuil (DEBUG < INFO) → false", ->
    assert.is_false log.level_enabled "DEBUG"

  it "niveau au seuil (INFO) → true", ->
    assert.is_true log.level_enabled "INFO"

  it "niveau au-dessus du seuil (WARN, ERROR) → true", ->
    assert.is_true log.level_enabled "WARN"
    assert.is_true log.level_enabled "ERROR"

  it "niveau inconnu (0) → false", ->
    assert.is_false log.level_enabled "PAS_UN_NIVEAU"

  -- rl_fingerprint : construction de la clé de rate-limiting (concat directe).
  it "rl_fingerprint concatène action_key + champs discriminants", ->
    fields = { mac_src: "aa:bb", qname: "x.example", qtype: "A" }
    fp = log.rl_fingerprint "ALLOW", fields, { "mac_src", "qname", "qtype" }
    assert.are.equal "ALLOW|aa:bb|x.example|A", fp

  it "rl_fingerprint : champ absent → 'nil' (préserve la sémantique d'origine)", ->
    fp = log.rl_fingerprint "BLOCK", { qname: "y.example" }, { "mac_src", "qname" }
    assert.are.equal "BLOCK|nil|y.example", fp

  it "rl_fingerprint : sans clé discriminante → action_key seul", ->
    assert.are.equal "neigh_refreshed", log.rl_fingerprint "neigh_refreshed", {}, {}
