-- tests/unit/log_fields_spec.moon
-- Garde-fou : tout nom de champ des tables littérales passées aux appels de
-- log dans src/**/*.moon doit être classé explicitement dans src/log.moon
-- (RL_IDENTITY_KEYS ou RL_VOLATILE_KEYS). Un champ non classé doit faire
-- échouer le test en le listant : sans cela, une nouvelle information
-- discriminante pourrait être silently ignorée par l'empreinte de
-- rate-limiting.

describe "inventaire des champs de log", ->
  local log_fields, saved_log, saved_config, log

  setup ->
    saved_log    = package.loaded["log"]
    saved_config = package.loaded["config"]
    package.loaded["log"] = nil
    package.loaded["config"] = { runtime: { log_level: "INFO" } }
    log = require "log"
    log_fields = dofile "tools/log_fields.lua"

  teardown ->
    package.loaded["log"]    = saved_log
    package.loaded["config"] = saved_config

  it "extrait les champs des tables littérales (témoin)", ->
    fields = log_fields.extract [[
      log_info -> { action: "x", qname: q, nested: { ignored: 1 } }
      log_debug -> with_meta {
        action: "y"
        rule_id: r
      }
      log_info -> fields   -- non littéral : ignoré
    ]]
    assert.is_true fields.action
    assert.is_true fields.qname
    assert.is_true fields.rule_id
    -- `nested` est un champ de premier niveau dont la valeur est une table :
    -- seules les clés de cette sous-table (`ignored`) doivent être ignorées.
    assert.is_true fields.nested
    assert.is_nil fields.ignored

  it "tous les champs de src/**/*.moon sont classés (identité ou volatil)", ->
    fields = log_fields.scan "src"
    unclassified = {}
    for name in pairs fields
      if name != "action" and not log.RL_IDENTITY_SET[name] and not log.RL_VOLATILE_SET[name]
        unclassified[#unclassified + 1] = name
    table.sort unclassified
    assert.are.same {}, unclassified

  it "les deux classements sont disjoints", ->
    both = {}
    for name in pairs log.RL_IDENTITY_SET
      if log.RL_VOLATILE_SET[name]
        both[#both + 1] = name
    table.sort both
    assert.are.same {}, both
