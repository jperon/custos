-- tests/unit/log_spec.moon
-- Couvre log.level_enabled (garde de niveau du hot path).
--
-- busted_setup stubbe `log` globalement ; on charge ici le VRAI module en
-- injectant un config minimal (runtime.log_level), puis on restaure les stubs
-- pour ne pas contaminer les specs suivantes.

ffi = require "ffi"

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
    assert.are.equal "action_quelconque", log.rl_fingerprint "action_quelconque", {}, {}

  -- Résolution de la règle : action complète, puis action sans le préfixe du
  -- worker, puis règle par défaut du NIVEAU même quand `action` est présent.
  -- Avant correctif, une action non listée n'était jamais limitée et les
  -- règles par défaut INFO:/DEBUG: ne s'appliquaient qu'aux messages sans
  -- `action` (quasiment aucun).
  describe "résolution de la règle de rate-limiting", ->
    before_each ->
      log._rl_reset!
      log.set_action_prefix ""

    it "INFO action non listée : défaut 60 s, empreinte sur les champs d'identité", ->
      f = { action: "action_inconnue", qname: "a.example", pid: 42 }
      assert.are.equal 0,  log.check_rl "INFO", f, 1000
      assert.are.equal -1, log.check_rl "INFO", f, 1001
      -- Fenêtre 60 s : à 1060 elle est expirée, réémission avec le compte 1.
      assert.are.equal 1,  log.check_rl "INFO", f, 1060
      assert.are.equal -1, log.check_rl "INFO", f, 1061

    it "WARN action non listée : défaut 60 s", ->
      f = { action: "warn_inconnue", peer: "10.0.0.2" }
      assert.are.equal 0,  log.check_rl "WARN", f, 2000
      assert.are.equal -1, log.check_rl "WARN", f, 2059
      assert.are.equal 1,  log.check_rl "WARN", f, 2060

    it "ERROR action non listée : défaut 10 s (erreurs jamais masquées longtemps)", ->
      f = { action: "error_inconnue", peer: "10.0.0.2" }
      assert.are.equal 0,  log.check_rl "ERROR", f, 3000
      assert.are.equal -1, log.check_rl "ERROR", f, 3009
      assert.are.equal 1,  log.check_rl "ERROR", f, 3010

    it "DEBUG action non listée : défaut 30 s", ->
      f = { action: "debug_inconnue", qname: "d.example" }
      assert.are.equal 0,  log.check_rl "DEBUG", f, 4000
      assert.are.equal -1, log.check_rl "DEBUG", f, 4029
      assert.are.equal 1,  log.check_rl "DEBUG", f, 4030

    it "champ d'identité différent → messages non fusionnés", ->
      f1 = { action: "identite", qname: "a.example", src_ip: "10.0.0.2" }
      f2 = { action: "identite", qname: "b.example", src_ip: "10.0.0.2" }
      assert.are.equal 0,  log.check_rl "INFO", f1, 5000
      assert.are.equal 0,  log.check_rl "INFO", f2, 5000
      assert.are.equal -1, log.check_rl "INFO", f1, 5001
      assert.are.equal -1, log.check_rl "INFO", f2, 5001

    it "champ volatil différent (pid, txid, compteur) → mêmes messages fusionnés", ->
      f1 = { action: "volatil", qname: "v.example", pid: 1, txid: "0x1", count: 1 }
      f2 = { action: "volatil", qname: "v.example", pid: 2, txid: "0x2", count: 99 }
      assert.are.equal 0,  log.check_rl "INFO", f1, 6000
      assert.are.equal -1, log.check_rl "INFO", f2, 6001

    it "action préfixée par le worker → règle spécifique (strip du préfixe)", ->
      log.set_action_prefix "response_"
      f = { action: "response_no_ipv6_for_client", client: "10.0.0.2" }
      assert.are.equal 0,  log.check_rl "INFO", f, 7000
      assert.are.equal -1, log.check_rl "INFO", f, 7119
      assert.are.equal 1,  log.check_rl "INFO", f, 7120
      autre = { action: "response_no_ipv6_for_client", client: "10.0.0.3" }
      assert.are.equal 0, log.check_rl "INFO", autre, 7120

    it "ALLOW action=response_dns_benchmark → règle ALLOW (mac_src, qname, qtype, 30 s)", ->
      f = { action: "response_dns_benchmark", mac_src: "aa:bb", qname: "x.test", qtype: "A", src_ip: "10.0.0.2" }
      assert.are.equal 0,  log.check_rl "ALLOW", f, 8000
      assert.are.equal -1, log.check_rl "ALLOW", f, 8001
      -- Fenêtre 30 s : expirée à 8030, réémission avec le compte 1.
      assert.are.equal 1,  log.check_rl "ALLOW", f, 8030
      autre = { action: "response_dns_benchmark", mac_src: "aa:bb", qname: "y.test", qtype: "A" }
      assert.are.equal 0, log.check_rl "ALLOW", autre, 8030

    it "BLOCK action=response_dns_benchmark → règle BLOCK (30 s)", ->
      f = { action: "response_dns_benchmark", mac_src: "aa:bb", qname: "b.test", qtype: "AAAA" }
      assert.are.equal 0,  log.check_rl "BLOCK", f, 9000
      assert.are.equal -1, log.check_rl "BLOCK", f, 9029
      assert.are.equal 1,  log.check_rl "BLOCK", f, 9030

    it "actions de cycle de vie jamais limitées", ->
      f = { action: "worker_died", name: "dns", pid: 123 }
      assert.are.equal 0, log.check_rl "WARN", f, 10000
      assert.are.equal 0, log.check_rl "WARN", f, 10001
      assert.are.equal 0, log.check_rl "WARN", f, 10002

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

  -- État partagé : table de hachage à taille fixe en
  -- mmap(MAP_SHARED|MAP_ANONYMOUS), créée au chargement du module donc héritée
  -- par tous les workers et leurs enfants après fork. Remplace la table Lua par
  -- processus : chaque enfant AUTH/DoH repartait d'un état vide (915 PID pour
  -- 915 lignes `auth_server_request_received`).
  describe "état partagé entre processus", ->
    before_each ->
      log._rl_reset!
      log.set_action_prefix ""

    it "_rl_reset vide l'état partagé", ->
      f = { action: "reset_test", qname: "r.example" }
      assert.are.equal 0,  log.check_rl "INFO", f, 1000
      assert.are.equal -1, log.check_rl "INFO", f, 1001
      log._rl_reset!
      assert.are.equal 0, log.check_rl "INFO", f, 1002

    it "un enfant forké alimente l'état vu par le parent", ->
      -- L'enfant insère une empreinte neuve (le parent ne l'a jamais vue) ;
      -- sans mémoire partagée, le parent repartirait de 0.
      f = { action: "fork_shared", qname: "fork.example" }
      pid = ffi.C.fork!
      if pid == 0
        log.check_rl "INFO", f, 7000
        ffi.C._exit 0
      assert.is_true pid > 0
      status = ffi.new "int[1]"
      assert.are.equal pid, ffi.C.waitpid pid, status, 0
      assert.are.equal -1, log.check_rl "INFO", f, 7000

    it "collision de slot : aucune des deux empreintes n'est supprimée à tort", ->
      -- Cherche deux empreintes distinctes dans le même slot (même index
      -- modulo RL_SLOTS) pour exercer le sondage linéaire.
      par_slot = {}
      a = nil
      b = nil
      for i = 1, 100000
        f = { action: "collision_test", qname: "c#{i}.example" }
        h = log._rl_hash "INFO", f
        slot = h % log.RL_SLOTS
        if par_slot[slot]
          if par_slot[slot].h != h
            a = par_slot[slot].f
            b = f
            break
        else
          par_slot[slot] = { h: h, f: f }
      assert.is_not_nil a
      assert.is_not_nil b
      assert.are.equal 0,  log.check_rl "INFO", a, 8000
      assert.are.equal 0,  log.check_rl "INFO", b, 8000
      assert.are.equal -1, log.check_rl "INFO", a, 8001
      assert.are.equal -1, log.check_rl "INFO", b, 8001
