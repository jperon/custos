-- tests/unit/pkg_default_config_spec.moon
-- Vérifie la configuration par défaut installée par le paquet OpenWrt :
-- packaging/openwrt/custos/files/etc/custos/config.moon → /etc/custos/config.moon
-- (cf. packaging/openwrt/custos/Makefile, `Package/custos/install`).
--
-- Deux contrôles distincts :
--   • chargement réel : le fichier est chargé par `src/config.moon` dans un
--     processus luajit séparé, avec CUSTOS_CONFIG_PATH + 
--     CUSTOS_REQUIRE_EXTERNAL_CONFIG=1 (comme l'init.d du paquet). Le module
--     construit sa table au chargement (`build!`, src/config.moon:621) et
--     busted_setup stubbe `package.loaded["config"]` : on ne peut pas le
--     charger dans le processus Busted sans polluer l'état global.
--   • schéma : le chargeur ne signale pas les clés inconnues (elles sont
--     fusionnées silencieusement dans les défauts), donc l'absence de clé
--     obsolète/invalide est vérifiée ici contre le miroir de DEFAULTS
--     (src/config.moon:183-393) et de doc/CONFIG.md.

PKG_CONFIG   = "packaging/openwrt/custos/files/etc/custos/config.moon"
PKG_MAKEFILE = "packaging/openwrt/custos/Makefile"
ORPHAN       = "packaging/openwrt/custos/files/etc/config.moon"
PROBE        = "tmp/pkg_default_config_probe.lua"

-- Le runner VM (make test-vm) ne copie que lua/ et tests/ : le paquet n'y est
-- pas. On marque alors les cas pending au lieu d'échouer.
skip_if_absent = ->
  f = io.open PKG_CONFIG, "r"
  unless f
    pending "packaging/ absent de cet environnement"
  f\close!

read_file = (path) ->
  f = assert io.open path, "r"
  content = f\read "*a"
  f\close!
  content

-- Chemins de clés acceptés, miroir de DEFAULTS (src/config.moon:183-393) et
-- des clés documentées par doc/CONFIG.md (dont celles sans défaut dans
-- DEFAULTS : cert/key TLS, session_key, close_grace, lowmem…).
VALID = {}
for path in *{
  "runtime",
  "runtime.log_level", "runtime.benchmark", "runtime.gc_pause",
  "runtime.gc_stepmul", "runtime.pid_file", "runtime.lowmem",
  "runtime.lowmem_threshold_kb",
  "nfqueue",
  "nfqueue.questions", "nfqueue.responses", "nfqueue.captive",
  "nfqueue.reject", "nfqueue.auth", "nfqueue.sni", "nfqueue.sip",
  "nfqueue.doh_vlan",
  "dns",
  "dns.port", "dns.ttl_grace", "dns.ttl_grace.grace", "dns.ttl_grace.min",
  "dns.ttl_grace.max", "dns.upstream_retry", "dns.upstream_retry.enabled",
  "dns.upstream_retry.max_attempts", "dns.upstream_retry.rcodes",
  "dns.upstream_retry.nxdomain_bad_ttl", "dns.upstream_retry.nxdomain_bad_max",
  "nft",
  "nft.family", "nft.family6", "nft.table", "nft.ip_timeout",
  "nft.sip_session_ttl", "nft.add_backoff_ms", "nft.add_failure_policy",
  "nft.ack_timeout_ms", "nft.extra_rules",
  "ipc",
  "ipc.pending_ttl", "ipc.match_retry", "ipc.match_retry.enabled",
  "ipc.match_retry.count", "ipc.match_retry.sleep_ms",
  "clients", "clients.expiry",
  "second_opinion", "second_opinion.resolvers", "second_opinion.budget_ms",
  "second_opinion.doh_budget_ms", "second_opinion.fail_open",
  "mac_learner", "mac_learner.query_sock", "mac_learner.entry_ttl",
  "auth",
  "auth.host", "auth.port", "auth.captive_port", "auth.cert", "auth.key",
  "auth.session_key", "auth.secrets", "auth.sessions_file", "auth.session_ttl",
  "auth.max_body", "auth.heartbeat_interval", "auth.idle_timeout",
  "auth.close_grace", "auth.client_timeout", "auth.challenge_ttl",
  "auth.allow_plaintext_login", "auth.register_rate_limit",
  "auth.register_rate_window", "auth.bridge_ifname", "auth.admin_users",
  "auth.admin_allow_all_when_empty",
  "sni",
  "sni.enabled", "sni.mode", "sni.placement", "sni.protocols",
  "sni.nft_failure_policy",
  "doh",
  "doh.enabled", "doh.port", "doh.upstream_ipv4", "doh.upstream_ipv6",
  "doh.upstream_port", "doh.upstream_timeout_ms", "doh.client_timeout",
  "doh.cert", "doh.key", "doh.prefer_ipv6", "doh.upstream_doh_url",
  "doh.upstream_doh_tls_verify",
  "events", "events.dir", "events.max_age_hours", "events.min_free_pct",
  "metrics", "metrics.enabled", "metrics.flush_interval", "metrics.max_rules",
  "rtp", "rtp.excluded_ports",
  "filter",
  "filter.domainlists_dir", "filter.custom_lists_dir", "filter.allow_localnets",
  "filter.lists_dir",
  "filter.captive_portal", "filter.safe_search", "filter.youtube_restrict",
  "filter.nets", "filter.macs", "filter.times", "filter.sources",
  "filter.users", "filter.userlists", "filter.rules", "filter.default_rules",
  "filter.dest_whitelist", "filter.allowed_domains", "filter.decision",
  "filter.decision.first_match_wins", "filter.decision.continue_to_next_rule",
}
  VALID[path] = true

-- Parcourt la table chargée et renvoie les chemins de clés déclarés.
-- Les éléments de listes (`filter.rules.1`, …) sont ignorés : leur contenu
-- est validé par filter/schema, pas ici.
touched_paths = (node, prefix, out) ->
  out or= {}
  for k, v in pairs node
    key = tostring k
    path = prefix and "#{prefix}.#{key}" or key
    out[#out + 1] = path unless key\match "^%d+$"
    if type(v) == "table" and next v
      touched_paths v, path, out
  out

-- Compile et exécute le fichier du paquet (MoonScript → table Lua).
load_packaged = ->
  moon = require "moonscript.base"
  chunk, load_err = moon.loadfile PKG_CONFIG
  assert.is_not_nil chunk, "compilation : #{tostring load_err}"
  ok, tbl = pcall chunk
  assert.is_true ok, "exécution : #{tostring tbl}"
  assert.is_table tbl
  tbl

-- Charge la configuration dans un luajit neuf (mêmes variables que l'init.d
-- du paquet : packaging/openwrt/custos/files/etc/init.d/custos:37).
-- Renvoie (sortie combinée stdout+stderr).
run_loader = ->
  probe = [==[
local path = assert(os.getenv("CUSTOS_CONFIG_PATH"), "CUSTOS_CONFIG_PATH manquant")
local config = require "config"
local m = assert(config.__meta, "config.__meta absent")
assert(m.external_loaded == true, "config externe non chargée")
assert(m.load_error == nil, "load_error: " .. tostring(m.load_error))
assert(m.path == path, "chemin chargé inattendu: " .. tostring(m.path))
assert(type(config.filter.rules) == "table", "filter.rules n'est pas une table")
assert(#config.filter.rules > 0, "aucune règle effective (default_rules perdues ?)")
assert(config.filter.safe_search == true, "safe_search désactivé")
assert(config.nfqueue.sni == "6", "nfqueue.sni inattendu: " .. tostring(config.nfqueue.sni))
assert(config.nfqueue.sni_log == nil, "clé obsolète nfqueue.sni_log encore lue")
assert(config.dns.forced_ttl == nil, "clé obsolète dns.forced_ttl encore lue")
assert(config.dns.ttl_grace.grace == 600, "ttl_grace.grace inattendu")
print("LOADER_OK")
]==]
  f = assert io.open PROBE, "w"
  f\write probe
  f\close!
  cmd = string.format(
    'LUA_PATH="lua/?.lua;lua/?/init.lua;;" CUSTOS_CONFIG_PATH=%q CUSTOS_REQUIRE_EXTERNAL_CONFIG=1 luajit %s 2>&1',
    PKG_CONFIG, PROBE)
  pipe = assert io.popen cmd, "r"
  out = pipe\read "*a"
  pipe\close!
  out = out\gsub "%s+$", ""
  out

describe "paquet OpenWrt — configuration par défaut", ->

  it "installe une seule configuration, à /etc/custos/config.moon, en conffile", ->
    skip_if_absent!
    mk = read_file PKG_MAKEFILE
    assert.is_truthy mk\find("$(INSTALL_CONF) $(CURDIR)/files/etc/custos/config.moon $(1)/etc/custos/config.moon", 1, true),
      "install : /etc/custos/config.moon absent du Makefile"
    conffiles = mk\match "define Package/custos/conffiles(.-)endef"
    assert.is_not_nil conffiles, "bloc conffiles absent du Makefile"
    assert.is_truthy conffiles\find("/etc/custos/config.moon", 1, true),
      "/etc/custos/config.moon doit être conffile (préservé à la mise à jour)"
    assert.is_nil mk\find("files/etc/config.moon", 1, true),
      "le paquet ne doit plus référencer le fichier orphelin files/etc/config.moon"

  it "ne contient aucune clé inconnue du schéma", ->
    skip_if_absent!
    for path in *touched_paths load_packaged!
      assert.is_true VALID[path] == true,
        "clé inconnue dans #{PKG_CONFIG} : #{path} (cf. src/config.moon DEFAULTS / doc/CONFIG.md)"

  it "ne contient aucune clé obsolète", ->
    skip_if_absent!
    cfg = load_packaged!
    assert.is_nil (cfg.dns or {}).forced_ttl, "dns.forced_ttl supprimé (TTL grace, cf. tests/e2e/migration_validation.moon:16-22)"
    assert.is_nil (cfg.nfqueue or {}).sni_log, "nfqueue.sni_log renommé nfqueue.sni (src/config.moon:200)"
    assert.is_nil (cfg.nft or {}).forced_ttl, "nft.forced_ttl supprimé"

  it "est acceptée par le chargeur réel, sans erreur ni avertissement", ->
    skip_if_absent!
    out = run_loader!
    assert.is_truthy out\find("LOADER_OK", 1, true), "chargement échoué : #{out}"
    assert.is_nil out\find("config: failed to load", 1, true), "avertissement du chargeur : #{out}"
    assert.is_nil out\find("config: %a", 1), "avertissement de configuration : #{out}"

  it "le fichier orphelin files/etc/config.moon a été supprimé", ->
    f = io.open ORPHAN, "r"
    exists = f != nil
    f\close! if f
    assert.is_false exists,
      "#{ORPHAN} doit être supprimé : son contenu est repris par #{PKG_CONFIG}"
