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

  it "TRACE (0) est plus verbeux que DEBUG : filtré au seuil INFO", ->
    assert.are.equal 0, log.get_log_level_num "TRACE"
    assert.is_false log.level_enabled "TRACE"

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

    it "champ identité explicite (rule_id) → deux événements distincts", ->
      f1 = { action: "ident_rule", rule_id: "rule_a" }
      f2 = { action: "ident_rule", rule_id: "rule_b" }
      assert.are.equal 0,  log.check_rl "INFO", f1, 6100
      assert.are.equal 0,  log.check_rl "INFO", f2, 6100
      assert.are.equal -1, log.check_rl "INFO", f1, 6101
      assert.are.equal -1, log.check_rl "INFO", f2, 6101

    it "family (IPv4 vs IPv6) est une identité → deux événements", ->
      f1 = { action: "ident_family", family: "ipv4" }
      f2 = { action: "ident_family", family: "ipv6" }
      assert.are.equal 0,  log.check_rl "INFO", f1, 6150
      assert.are.equal 0,  log.check_rl "INFO", f2, 6150
      assert.are.equal -1, log.check_rl "INFO", f1, 6151
      assert.are.equal -1, log.check_rl "INFO", f2, 6151

    it "champ inconnu (non classé) traité comme identité", ->
      f1 = { action: "ident_inconnu", champ_inconnu_xyz: "a" }
      f2 = { action: "ident_inconnu", champ_inconnu_xyz: "b" }
      assert.are.equal 0,  log.check_rl "INFO", f1, 6200
      assert.are.equal 0,  log.check_rl "INFO", f2, 6200
      assert.are.equal -1, log.check_rl "INFO", f1, 6201
      assert.are.equal -1, log.check_rl "INFO", f2, 6201

    it "champ volatil seul (bytes) → seconde ligne supprimée puis suppressed=1", ->
      f1 = { action: "volatil_bytes", qname: "vb.example", bytes: 10 }
      f2 = { action: "volatil_bytes", qname: "vb.example", bytes: 99 }
      assert.are.equal 0,  log.check_rl "INFO", f1, 6300
      assert.are.equal -1, log.check_rl "INFO", f2, 6301
      -- Fenêtre INFO de 60 s : à 6360 la ligne réapparaît avec le compte.
      assert.are.equal 1,  log.check_rl "INFO", f2, 6360

    it "empreinte par défaut indépendante de l'ordre de parcours des champs", ->
      f1 = { action: "ordre", rule_id: "r1", path: "/a" }
      f2 = { path: "/a", rule_id: "r1", action: "ordre" }
      assert.are.equal log._rl_hash("INFO", f1), log._rl_hash("INFO", f2)

    it "rl_fingerprint par défaut : ordre des champs normalisé", ->
      f1 = { action: "fp_ordre", rule_id: "r1", path: "/a" }
      f2 = { path: "/a", rule_id: "r1", action: "fp_ordre" }
      assert.are.equal (log.rl_fingerprint "INFO", f1, log.RL_IDENTITY_KEYS),
                        (log.rl_fingerprint "INFO", f2, log.RL_IDENTITY_KEYS)

    it "doh_handshake_failed reste WARN, limité par IP cliente sur 60 s", ->
      log.set_action_prefix "doh_"
      f1 = { action: "doh_handshake_failed", peer: "10.0.0.2", attempts: 1, err: "timeout" }
      f2 = { action: "doh_handshake_failed", peer: "10.0.0.2", attempts: 9, err: "timeout" }
      autre = { action: "doh_handshake_failed", peer: "10.0.0.3", attempts: 1, err: "timeout" }
      assert.are.equal 0,  log.check_rl "WARN", f1, 7300
      assert.are.equal -1, log.check_rl "WARN", f2, 7301
      assert.are.equal 0,  log.check_rl "WARN", autre, 7302
      assert.are.equal 1,  log.check_rl "WARN", f2, 7360
      log.set_action_prefix ""

    it "action préfixée par le worker → règle spécifique (strip du préfixe)", ->
      log.set_action_prefix "response_"
      f = { action: "response_no_ipv6_for_client", client: "10.0.0.2" }
      assert.are.equal 0,  log.check_rl "INFO", f, 7000
      assert.are.equal -1, log.check_rl "INFO", f, 7119
      assert.are.equal 1,  log.check_rl "INFO", f, 7120
      autre = { action: "response_no_ipv6_for_client", client: "10.0.0.3" }
      assert.are.equal 0, log.check_rl "INFO", autre, 7120

    it "ALLOW action=response_dns_benchmark → jamais limité (instrumentation)", ->
      log.set_action_prefix "response_"
      f = { action: "response_dns_benchmark", mac_src: "aa:bb", qname: "x.test", qtype: "A", src_ip: "10.0.0.2", q_to_response_ms: 12 }
      assert.are.equal 0,  log.check_rl "ALLOW", f, 8000
      assert.are.equal 0,  log.check_rl "ALLOW", f, 8001
      assert.are.equal 0,  log.check_rl "ALLOW", f, 8002
      -- L'objet de l'option benchmark : chaque échantillon est mesuré, donc
      -- aucune ligne ne doit disparaître dans une fenêtre de 30 s.
      f2 = { action: "response_dns_benchmark", mac_src: "aa:bb", qname: "x.test", qtype: "A", q_to_response_ms: 99 }
      assert.are.equal 0,  log.check_rl "ALLOW", f2, 8002
      log.set_action_prefix ""

    it "BLOCK action=response_dns_benchmark → jamais limité (instrumentation)", ->
      log.set_action_prefix "response_"
      f = { action: "response_dns_benchmark", mac_src: "aa:bb", qname: "b.test", qtype: "AAAA" }
      assert.are.equal 0,  log.check_rl "BLOCK", f, 9000
      assert.are.equal 0,  log.check_rl "BLOCK", f, 9001
      assert.are.equal 0,  log.check_rl "BLOCK", f, 9002
      log.set_action_prefix ""

    it "actions de cycle de vie jamais limitées", ->
      f = { action: "worker_died", name: "dns", pid: 123 }
      assert.are.equal 0, log.check_rl "WARN", f, 10000
      assert.are.equal 0, log.check_rl "WARN", f, 10001
      assert.are.equal 0, log.check_rl "WARN", f, 10002
      -- Non tautologique : une action voisine non exemptée est bien limitée.
      voisine = { action: "worker_disabled", name: "dns" }
      assert.are.equal 0,  log.check_rl "WARN", voisine, 10000
      assert.are.equal -1, log.check_rl "WARN", voisine, 10001

    it "événements d'audit jamais limités (login, logout/session, mot de passe)", ->
      log.set_action_prefix "auth_"
      for action in *{"server_login_success", "server_password_changed", "server_bye_grace", "server_ping_session_invalidated", "user_session_expired", "user_session_removed"}
        f = { action: "auth_#{action}", user: "alice", ip: "10.0.0.2" }
        assert.are.equal 0, log.check_rl "INFO", f, 12000
        assert.are.equal 0, log.check_rl "INFO", f, 12001
        assert.are.equal 0, log.check_rl "INFO", f, 12002
      log.set_action_prefix ""

    it "reload du superviseur jamais limité (famille rechargement)", ->
      f = { action: "supervisor_sighup_reload" }
      assert.are.equal 0, log.check_rl "INFO", f, 12100
      assert.are.equal 0, log.check_rl "INFO", f, 12101
      assert.are.equal 0, log.check_rl "INFO", f, 12102

    it "échec d'authentification limité par (ip, utilisateur), pas exempté", ->
      log.set_action_prefix "auth_"
      f1 = { action: "auth_server_login_nonce_rejected", ip: "10.0.0.2", user: "alice", err: "expired" }
      f2 = { action: "auth_server_login_nonce_rejected", ip: "10.0.0.2", user: "alice", err: "expired" }
      assert.are.equal 0,  log.check_rl "WARN", f1, 12200
      assert.are.equal -1, log.check_rl "WARN", f2, 12201
      -- Un autre utilisateur ou une autre IP reste un événement distinct.
      autre_user = { action: "auth_server_login_nonce_rejected", ip: "10.0.0.2", user: "bob", err: "expired" }
      autre_ip   = { action: "auth_server_login_nonce_rejected", ip: "10.0.0.3", user: "alice", err: "expired" }
      assert.are.equal 0, log.check_rl "WARN", autre_user, 12202
      assert.are.equal 0, log.check_rl "WARN", autre_ip, 12203
      -- Cause différente : conservée (err est discriminant).
      autre_err = { action: "auth_server_login_nonce_rejected", ip: "10.0.0.2", user: "alice", err: "invalid" }
      assert.are.equal 0, log.check_rl "WARN", autre_err, 12204
      log.set_action_prefix ""

    it "_rl_never_limited : strip du préfixe worker", ->
      log.set_action_prefix "response_"
      assert.is_true  log._rl_never_limited "response_worker_died"
      assert.is_true  log._rl_never_limited "worker_died"
      assert.is_true  log._rl_never_limited "response_dns_benchmark"
      assert.is_false log._rl_never_limited "response_action_ordinaire"
      assert.is_false log._rl_never_limited nil
      log.set_action_prefix ""

    it "champs d'identité ajoutés (P2.1) : deux valeurs → deux événements", ->
      for key in *{"ip_src", "ip_dst", "username", "host", "resolver", "protocol", "l4_proto", "rcode", "errno", "source", "direction", "version", "verdict", "backend"}
        f1 = { action: "ident_#{key}" }
        f1[key] = "valeur1"
        f2 = { action: "ident_#{key}" }
        f2[key] = "valeur2"
        assert.are.equal 0,  log.check_rl "INFO", f1, 11000
        assert.are.equal 0,  log.check_rl "INFO", f2, 11000
        assert.are.equal -1, log.check_rl "INFO", f1, 11001
        assert.are.equal -1, log.check_rl "INFO", f2, 11001

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

  -- Repli par processus, saturation, recyclage et horloge : les seams
  -- `_rl_force_fallback`, `_rl_slot_get/_rl_slot_set` et `rl_stats` permettent
  -- de forcer les branches sans dépendre d'une course réelle.
  describe "repli, saturation et recyclage", ->
    before_each ->
      log._rl_force_fallback false
      log._rl_reset!
      log._rl_force_fallback true
      log._rl_reset!      -- vide aussi le repli (les deux tables)
      log._rl_force_fallback false
      log.set_action_prefix ""

    after_each ->
      log._rl_force_fallback false
      log._rl_reset!
      log._rl_force_fallback true
      log._rl_reset!
      log._rl_force_fallback false
      log.set_action_prefix ""

    it "rl_shared() vrai et rl_stats cohérent quand mmap est disponible", ->
      assert.is_true log.rl_shared!
      st = log.rl_stats!
      assert.is_true st.shared
      assert.are.equal 0, st.saturated
      assert.are.equal log.RL_SLOTS, st.slots

    it "repli forcé : rl_shared() faux, limiteur toujours fonctionnel", ->
      log._rl_force_fallback true
      assert.is_false log.rl_shared!
      assert.is_false log.rl_stats!.shared
      f = { action: "fallback_test", qname: "f.example" }
      assert.are.equal 0,  log.check_rl "INFO", f, 1000
      assert.are.equal -1, log.check_rl "INFO", f, 1001
      assert.are.equal 1,  log.check_rl "INFO", f, 1060
      -- Retour à l'état partagé : l'entrée du repli n'y figure pas.
      log._rl_force_fallback false
      assert.is_true log.rl_shared!
      assert.are.equal 0, log.check_rl "INFO", f, 1061

    it "saturation : sondage épuisé → journalisation non limitée + compteur", ->
      f = { action: "saturation_test", qname: "sat.example" }
      h = log._rl_hash "INFO", f
      slot = h % log.RL_SLOTS
      -- Occupe les RL_PROBE_MAX slots du sondage par des empreintes vivantes
      -- (fenêtre de 60 s non expirée) : aucun recyclage possible.
      for i = 0, log.RL_PROBE_MAX - 1
        idx = (slot + i) % log.RL_SLOTS
        log._rl_slot_set idx, 0x10000000 + i, 5000, 5060, 0
      before = log.rl_stats!.saturated
      assert.are.equal 0, log.check_rl "INFO", f, 5000
      assert.are.equal 0, log.check_rl "INFO", f, 5001
      assert.are.equal before + 2, log.rl_stats!.saturated

    it "recyclage d'un slot expiré par une autre empreinte (échéance propre)", ->
      f = { action: "recycle_test", qname: "rec.example" }
      h = log._rl_hash "INFO", f
      slot = h % log.RL_SLOTS
      -- Autre empreinte, expirée depuis peu (10 s) : l'ancien code exigeait
      -- RL_MAX_WINDOW (120 s) et ne recyclait pas ce slot.
      log._rl_slot_set slot, 0x0BADF00D, 1990, 2000, 7
      assert.are.equal 0, log.check_rl "INFO", f, 2000
      s = log._rl_slot_get slot
      assert.are.equal h,    s.hash
      assert.are.equal 2000, s.ts
      assert.are.equal 2060, s.expires
      assert.are.equal 0,    s.count

    it "horloge en marche arrière : entrée future traitée comme expirée", ->
      f = { action: "clock_back", qname: "cb.example" }
      h = log._rl_hash "INFO", f
      slot = h % log.RL_SLOTS
      log._rl_slot_set slot, h, 5000, 5060, 3
      -- epoch < ts (step NTP) : on rend le compteur et on réinitialise, au lieu
      -- de supprimer indéfiniment.
      assert.are.equal 3, log.check_rl "INFO", f, 4000
      assert.are.equal 0, log._rl_slot_get(slot).count

    it "repli : purge des entrées expirées plutôt que vidage global", ->
      log._rl_force_fallback true
      vivante = { action: "fb_vivante", qname: "vivante.example" }
      -- Entrée encore dans sa fenêtre (INFO 60 s) au moment de la purge.
      log.check_rl "INFO", vivante, 2000
      for i = 1, log.RL_SLOTS - 1
        f = { action: "fb_old_#{i}", qname: "old#{i}.example" }
        log.check_rl "INFO", f, 1000   -- expirées à 1060
      -- Table pleine : l'insertion déclenche la purge des expirées ; l'entrée
      -- vivante doit survivre (l'ancien code vidait toute la table).
      neuve = { action: "fb_neuve", qname: "neuve.example" }
      log.check_rl "INFO", neuve, 2000
      assert.are.equal -1, log.check_rl "INFO", vivante, 2001

  describe "formatage des lignes", ->
    it "format_line ajoute suppressed=N quand N > 0", ->
      line = log.format_line 1234, 42, "INFO", { action: "x", qname: "q.example" }, 7
      assert.is_truthy line\find "suppressed=7", 1, true
      assert.is_truthy line\find "qname=q.example", 1, true
      assert.is_truthy line\find "[1234] [42] INFO", 1, true

    it "format_line n'ajoute suppressed que si N > 0", ->
      line = log.format_line 1, 2, "INFO", { action: "x" }, 0
      assert.is_nil line\find "suppressed=", 1, true

    it "format_line met entre guillemets les valeurs contenant un espace", ->
      line = log.format_line 1, 2, "WARN", { action: "x", reason: "deux mots" }, 0
      assert.is_truthy line\find 'reason="deux mots"', 1, true

  describe "constante mmap", ->
    it "_map_anonymous choisit 0x800 sur MIPS, 0x20 ailleurs", ->
      assert.are.equal 0x800, log._map_anonymous "mips"
      assert.are.equal 0x800, log._map_anonymous "mips64"
      assert.are.equal 0x20,  log._map_anonymous "x64"
      assert.are.equal 0x20,  log._map_anonymous "arm64"
      assert.are.equal 0x20,  log._map_anonymous nil

    it "MAP_ANONYMOUS courant correspond à l'architecture d'exécution", ->
      assert.are.equal log._map_anonymous(jit and jit.arch), log.MAP_ANONYMOUS
