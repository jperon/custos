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

  -- RL_CONFIG.captive_redirect doit correspondre à l'action réellement émise
  -- par worker_captive (action: "redirect", préfixée "captive_" → "captive_redirect")
  -- et à des champs qu'il émet vraiment (pas de "path", qui n'existe pas dans
  -- ces logs). Un mismatch ici désactive silencieusement le rate-limit (bug
  -- historique corrigé : la config référençait "captive_redirect" alors que
  -- l'action loggée était "captive_redirect_captive").
  it "RL_CONFIG.captive_redirect discrimine sur des champs existants (pas 'path')", ->
    cfg = log.RL_CONFIG.captive_redirect
    assert.is_not_nil cfg
    assert.are.same { "ip" }, cfg.keys

  -- Purge bornée de _rl : sans elle, une entrée par (MAC, domaine, type) vue
  -- reste en mémoire pour toute la vie du worker.
  describe "purge bornée de _rl", ->
    count_rl = ->
      n = 0
      for _ in pairs log._rl
        n += 1
      n

    before_each -> log._rl_reset!

    it "conserve la sémantique du rate-limit (fenêtre par action)", ->
      f = { mac_src: "aa:bb", qname: "x.test", qtype: "A" }
      -- Fenêtre ALLOW = 30 s.
      assert.are.equal 0,  log.check_rl "ALLOW", f, 1000
      assert.are.equal -1, log.check_rl "ALLOW", f, 1001
      assert.are.equal -1, log.check_rl "ALLOW", f, 1029
      assert.are.equal 2,  log.check_rl "ALLOW", f, 1030
      assert.are.equal -1, log.check_rl "ALLOW", f, 1031

    it "purge les entrées expirées au plus toutes les N insertions", ->
      n = log.RL_PURGE_EVERY

      -- Fenêtre ALLOW = 30 s.
      for i = 1, n
        log.check_rl "ALLOW", { mac_src: "aa:bb", qname: "a#{i}.test", qtype: "A" }, 1000
      assert.are.equal n, count_rl!

      -- Toujours dans la fenêtre : la purge ne doit rien supprimer.
      for i = 1, n
        log.check_rl "ALLOW", { mac_src: "aa:bb", qname: "b#{i}.test", qtype: "A" }, 1005
      assert.are.equal 2 * n, count_rl!

      -- Entrées de 1000 (exp. 1030) et 1005 (exp. 1035) expirées : seules
      -- les N entrées du troisième lot restent.
      for i = 1, n
        log.check_rl "ALLOW", { mac_src: "aa:bb", qname: "c#{i}.test", qtype: "A" }, 1040
      assert.are.equal n, count_rl!

  -- ── Rate-limiting des anomalies d'appariement question/réponse ──────
  -- `check_rl` cherche `RL_CONFIG[fields.action]` et retourne 0 (AUCUN
  -- rate-limiting) quand l'action n'a pas d'entrée : la clé générique `INFO`
  -- n'est utilisée que si `fields.action` est nil. Un log_info portant une
  -- action n'est donc JAMAIS rate-limité sans entrée dédiée. Ces entrées sont
  -- la condition d'efficacité des nouvelles traces (orphan drop, écrasement de
  -- clé IPC) : à 400 réponses orphelines/s, une trace non rate-limitée
  -- produirait 400 lignes/s.
  describe "rate-limiting des anomalies d'appariement", ->
    before_each -> log._rl_reset!

    it "sans entrée dédiée, une action INFO n'est pas rate-limitée (piège)", ->
      assert.is_nil log.RL_CONFIG.action_sans_entree
      f = { action: "action_sans_entree" }
      assert.are.equal 0, log.check_rl "INFO", f, 1000
      assert.are.equal 0, log.check_rl "INFO", f, 1001

    for action in *{"response_orphan_dropped", "ipc_pending_overwrite",
                    "ipc_pending_overwrite_divergent"}
      it "#{action} : une seule ligne par fenêtre de 10 s, occurrences agrégées", ->
        cfg = log.RL_CONFIG[action]
        assert.is_not_nil cfg, "entrée RL_CONFIG manquante : trace non bornée"
        assert.are.same {}, cfg.keys, "agrégation par action (pas de clé parasite)"
        f = { action: action }
        assert.are.equal 0,  log.check_rl "INFO", f, 1000  -- première : émise
        assert.are.equal -1, log.check_rl "INFO", f, 1001  -- supprimée
        assert.are.equal -1, log.check_rl "INFO", f, 1009
        assert.are.equal 2,  log.check_rl "INFO", f, 1010  -- fenêtre écoulée
        assert.are.equal -1, log.check_rl "INFO", f, 1011

      it "#{action} : niveau WARN rate-limité aussi (traces mixtes)", ->
        f = { action: action }
        assert.are.equal 0,  log.check_rl "WARN", f, 2000
        assert.are.equal -1, log.check_rl "WARN", f, 2001
