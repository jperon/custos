-- tests/unit/filter/trr_confirmation_spec.moon
-- Nom de confirmation du résolveur DoH (TRR) de Firefox
-- (`network.trr.confirmationNS`, défaut `example.com`).
--
-- Firefox valide son résolveur DoH en résolvant ce nom : sans NOERROR il
-- journalise TRR_RCODE_FAIL et retombe sur le DNS classique. Le nom doit donc
-- recevoir une résolution amont réelle quel que soit l'état d'authentification,
-- sans jamais créer d'entrée d'allowlist nft (aucun autre nom ouvert).
--
-- Ces tests portent sur les règles par défaut réellement compilées : la même
-- décision alimente le plan UDP (worker_questions) et le plan DoH (doh.query).

-- Stubs avant tout require de module de production
package.loaded["ipc"] or= { register_modifier: -> nil }
package.loaded["ip_whitelist"] or= { init: -> nil, cleanup: -> nil }
package.loaded["dns_ede"] or= {
  strip_dns_rr:     (raw, _t) -> raw
  add_ede_modified: (raw, _r) -> raw
  clear_ad_bit:     (raw) -> raw
}
package.loaded["auth.user_sessions"] = { get_session: -> nil }
package.loaded["mac_learner_ipc"] = { get_mac: -> nil }

-- Session courante contrôlée par les tests (nil = client anonyme).
_sessions = { current: nil }
package.loaded["auth.sessions"] = {
  session_for_mac:   (mac, src_ip, path) -> _sessions.current
  enrich_session_ip: -> nil
  bind_session_mac:  -> nil
  user_for_mac:      -> nil
}

ffi = require "ffi"
pcall ffi.cdef, [[int setenv(const char*, const char*, int); int unsetenv(const char*);]]

CONFIG_OVERRIDE = "tmp/__trr_confirmation_config__.moon"

--- Charge config.moon, avec une surcharge MoonScript éventuelle.
-- @tparam string|nil override Contenu MoonScript retournant une table partielle.
-- @treturn table Configuration normalisée.
load_config = (override=nil) ->
  package.loaded["config"] = nil
  if override
    f = assert io.open CONFIG_OVERRIDE, "w"
    f\write override
    f\close!
    ffi.C.setenv "CUSTOS_CONFIG_PATH", CONFIG_OVERRIDE, 1
  else
    ffi.C.setenv "CUSTOS_CONFIG_PATH", "tmp/__no_config_for_test__.moon", 1
  cfg = require "config"
  ffi.C.unsetenv "CUSTOS_CONFIG_PATH"
  os.remove CONFIG_OVERRIDE if override
  cfg

--- Compile les règles du filtre (recharge les conditions pour les stubs).
-- @tparam table cfg Configuration normalisée.
-- @treturn table Règles compilées (filter.rule.compile_rules).
compile = (cfg) ->
  package.loaded["filter.conditions.from_user"] = nil
  package.loaded["filter.rule"] = nil
  rule = require "filter.rule"
  rule.compile_rules cfg.filter

--- Décide pour un nom et un état d'authentification donné.
-- @tparam table      compiled Règles compilées.
-- @tparam string     name     Nom interrogé (casse basse).
-- @tparam table|nil  session  Session active, ou nil pour un client anonyme.
-- @treturn table decide_meta
decide = (compiled, name, session) ->
  _sessions.current = session
  require("filter.rule").decide_meta compiled,
    { domain: name, src_ip: "10.0.0.1", mac: "aa:bb:cc:dd:ee:01" }

--- Décision d'injection nft réellement calculée par les callbacks on_response.
-- @tparam table  compiled Règles compilées.
-- @tparam table  meta     Résultat de `decide`.
-- @treturn boolean true si les IP résolues seraient injectées dans nft.
inject_nft = (compiled, meta) ->
  ctx = require("filter.rule").run_on_response compiled, meta.response_rule_ids,
    "\0\0\0\0\0\0\0\0\0\0\0\0", meta.reason
  ctx.inject_nft

--- Retrouve les règles par défaut portant un nom donné dans `to_domains`.
-- @tparam table  cfg  Configuration normalisée.
-- @tparam string name Nom recherché.
-- @treturn table Liste des règles concernées.
rules_for = (cfg, name) ->
  out = {}
  for r in *cfg.filter.rules
    domains = (r.conditions and r.conditions.to_domains) or {}
    for d in *domains
      if d == name
        out[#out + 1] = r
        break
  out

ALICE = { user: "alice", mac: "aa:bb:cc:dd:ee:01" }

describe "nom de confirmation TRR de Firefox", ->

  after_each ->
    _sessions.current = nil

  it "liste dédiée : example.com seul, une seule règle dnsonly", ->
    cfg = load_config!
    assert.same { "example.com" }, cfg.filter.trr_confirmation
    found = rules_for cfg, "example.com"
    assert.equals 1, #found
    assert.same { "dnsonly" }, found[1].actions
    -- Le nom n'apparaît dans aucune autre règle par défaut (pas de allow
    -- authentifié, pas de sonde captive) : aucune autre voie n'est ouverte.
    for r in *cfg.filter.rules
      domains = (r.conditions and r.conditions.to_domains) or {}
      continue if r == found[1]
      for d in *domains
        assert.is_not.equals "example.com", d

  it "client anonyme : example.com → dnsonly, sans injection nft", ->
    compiled = compile load_config!
    meta = decide compiled, "example.com", nil
    assert.is_true meta.verdict
    assert.equals "DNS only", meta.reason\match "^DNS only"
    assert.is_false inject_nft compiled, meta

  it "client authentifié : même dnsonly (aucune entrée nft non plus)", ->
    compiled = compile load_config!
    meta = decide compiled, "example.com", ALICE
    assert.is_true meta.verdict
    assert.equals "DNS only", meta.reason\match "^DNS only"
    assert.is_false inject_nft compiled, meta

  it "sous-domaine couvert, nom label-adjacent non ouvert", ->
    compiled = compile load_config!
    sub = decide compiled, "www.example.com", nil
    assert.is_true sub.verdict
    assert.equals "DNS only", sub.reason\match "^DNS only"
    -- `to_domains` matche par labels (`to_domain.moon:42-47`), pas par
    -- sous-chaîne : ces noms ne sont PAS couverts par la liste.
    for name in *{ "notexample.com", "example.com.evil.net", "example.co" }
      meta = decide compiled, name, nil
      assert.is_false meta.verdict, "#{name} ne doit pas être autorisé"

  it "les autres noms restent refusés pour un client anonyme (non-régression)", ->
    compiled = compile load_config!
    meta = decide compiled, "site.example.net", nil
    assert.is_false meta.verdict
    assert.equals "No matching rule (default deny)", meta.reason

  it "les sondes CAPTIVE_PROBES gardent allow/dnsonly (non-régression)", ->
    compiled = compile load_config!
    for name in *{ "captive.apple.com", "firefox-portal-detection.com", "msftconnecttest.com", "connectivitycheck.gstatic.com" }
      anon = decide compiled, name, nil
      assert.is_true anon.verdict, "#{name} (anonyme)"
      assert.equals "DNS only", anon.reason\match "^DNS only"
      assert.is_false inject_nft(compiled, anon), "#{name} ne doit pas injecter (anonyme)"
      auth = decide compiled, name, ALICE
      assert.is_true auth.verdict, "#{name} (authentifié)"
      assert.equals "Allowed by rule", auth.reason\match "^Allowed by rule"
      assert.is_true inject_nft(compiled, auth), "#{name} doit injecter (authentifié)"

  it "le canari DoH Firefox reste NXDOMAIN", ->
    compiled = compile load_config!
    meta = decide compiled, "use-application-dns.net", nil
    assert.is_false meta.verdict
    assert.truthy meta.description\match "DoH"

  it "configurable : la liste remplace example.com", ->
    cfg = load_config [[{ filter: { safe_search: false, trr_confirmation: { "Example.ORG." } } }]]
    assert.same { "example.org" }, cfg.filter.trr_confirmation
    compiled = compile cfg
    assert.is_true (decide compiled, "example.org", nil).verdict
    assert.is_false (decide compiled, "example.com", nil).verdict
    -- Une seule règle créée, toujours dnsonly (aucun allow authentifié).
    found = rules_for cfg, "example.org"
    assert.equals 1, #found
    assert.same { "dnsonly" }, found[1].actions

  it "valeur false : règles TRR retirées, captives conservées", ->
    cfg = load_config [[{ filter: { safe_search: false, trr_confirmation: false } }]]
    assert.same {}, cfg.filter.trr_confirmation
    compiled = compile cfg
    assert.is_false (decide compiled, "example.com", nil).verdict
    assert.is_true (decide compiled, "captive.apple.com", nil).verdict

  it "entrées invalides ignorées, type invalide → défaut", ->
    cfg = load_config [[{ filter: { safe_search: false, trr_confirmation: { "bad name!", "Example.NET" } } }]]
    assert.same { "example.net" }, cfg.filter.trr_confirmation
    cfg = load_config [[{ filter: { safe_search: false, trr_confirmation: 42 } }]]
    assert.same { "example.com" }, cfg.filter.trr_confirmation

  it "default_rules: {} désactive aussi la règle TRR", ->
    cfg = load_config [[{ filter: { safe_search: false, default_rules: {}, rules: {
      { description: "Interne", actions: {"allow"}, conditions: { to_domain: "interne.test" } }
    } } }]]
    compiled = compile cfg
    assert.is_false (decide compiled, "example.com", nil).verdict
    assert.is_true (decide compiled, "interne.test", nil).verdict
