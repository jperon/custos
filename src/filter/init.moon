-- src/filter/init.moon
-- API publique du gestionnaire d'autorisations.
-- Remplace src/allowlist.moon.
--
-- Interface :
--   filter.load()         — charge la configuration et compile les règles
--   filter.decide(req)    — retourne true/false + raison
--   filter.reload()       — recharge à chaud (SIGHUP)
--
-- req = { domain, src_ip, mac, ts }
--   domain  : nom DNS demandé (string)
--   src_ip  : adresse IP source (string)
--   mac     : adresse MAC source (string, ex. "aa:bb:cc:dd:ee:ff")
--   ts      : timestamp Unix (number, os.time())

{ :ffi, :libc } = require "ffi_defs"
{ :compile_rules, decide: _decide, decide_meta: _decide_meta, on_response_for: _on_response_for, run_on_response: _run_on_response } = require "filter.rule"
{ :log_info, :log_warn, :log_debug } = require "log"
{ :inject_localnets } = require "filter.localnets"
ip_whitelist = require "ip_whitelist"
config = require "config"

rules = nil
auth_cfg_cache = nil
sni_cfg_cache = nil
decision_cfg = nil

clone = (v) ->
  return v unless type(v) == "table"
  out = {}
  for k, item in pairs v
    out[k] = clone item
  out

count_keys = (t) ->
  return 0 unless type(t) == "table"
  n = 0
  for _ in pairs t
    n += 1
  n

count_user_entries = (userlists) ->
  return 0 unless type(userlists) == "table"
  n = 0
  for _, users in pairs userlists
    if type(users) == "table"
      n += #users
  n

build_filter_cfg = ->
  root = config.filter or {}
  cfg = clone root
  cfg.nets = cfg.nets or {}
  cfg.macs = cfg.macs or {}
  cfg.times = cfg.times or {}
  cfg.sources = cfg.sources or {}
  cfg.rules = cfg.rules or {}
  cfg.users = cfg.users or {}
  cfg.userlists = cfg.userlists or cfg.users or {}
  cfg.users = cfg.users or cfg.userlists or {}
  cfg.dest_whitelist = cfg.dest_whitelist or {}
  cfg.allowed_domains = cfg.allowed_domains or {}
  cfg.auth = clone(config.auth or {})

  -- Transition minimale: si aucune règle n'est fournie, on génère
  -- "allow allowed_domains" puis "deny default".
  if #cfg.rules == 0 and #cfg.allowed_domains > 0
    log_warn -> { action: "filter_rules_missing", detail: "falling back to allowlist domains" }
    cfg.rules = {
      {
        description: "Builtin allowlist domains"
        actions: { "allow" }
        conditions: {
          to_domains: clone cfg.allowed_domains
        }
      }
      {
        description: "Builtin default deny"
        actions: { "deny" }
      }
    }

  cfg

-- ── Chargement ────────────────────────────────────────────────────
--- Charge la configuration du filtre depuis /etc/custos/config.moon.
-- Peut être appelé à nouveau pour recharger (hot-reload).
-- @treturn nil
load = ->
  cfg = build_filter_cfg!
  unless cfg
    log_warn -> { action: "filter_load_failed", err: "invalid runtime config" }
    return
  root_rules = #(config.filter and config.filter.rules or {})
  fallback_builtin = root_rules == 0 and #cfg.rules > 0
  cfg_meta = config.__meta or {}
  log_debug -> {
    action: "filter_config_source"
    path: cfg_meta.path or "unknown"
    env_path: cfg_meta.env_path or ""
    external_loaded: cfg_meta.external_loaded and 1 or 0
    load_error: cfg_meta.load_error or ""
    configured_rules: root_rules
    effective_rules: #cfg.rules
    fallback_builtin: fallback_builtin and 1 or 0
  }
  rules = compile_rules cfg
  auth_cfg_cache = cfg.auth
  sni_cfg_cache  = cfg.sni
  decision_cfg = cfg.decision or {}
  whitelist = cfg.dest_whitelist or {}

  -- Injection dynamique des réseaux locaux (Basé sur l'option allow_localnets)
  inject_localnets cfg, whitelist

  ip_whitelist.init whitelist
  -- NFT extra rules are applied once at process startup by worker_questions
  -- (moved out of filter.load to avoid re-inserting rules on hot-reload)
  n = #rules
  log_info -> {
    action: "filter_loaded"
    rules: n
    dest_whitelist: #whitelist
    userlists: count_keys cfg.userlists
    users: count_user_entries cfg.userlists
  }

-- ── Décision ─────────────────────────────────────────────────────
--- Décide du verdict pour une requête DNS.
-- @tparam table req {domain, src_ip, mac, ts}
-- @treturn boolean true = autoriser, false = bloquer
-- @treturn string  Raison (pour le log)
-- @treturn string  Description de la règle ayant matché (pour le log)
decide = (req) ->
  unless rules
    log_warn -> { action: "filter_not_loaded", domain: req and req.domain or "unknown" }
    return false, "filter not loaded", nil
  _decide rules, req, decision_cfg

decide_meta = (req) ->
  unless rules
    log_warn -> { action: "filter_not_loaded", domain: req and req.domain or "unknown" }
    return { verdict: false, reason: "filter not loaded", rule_id: nil, timeout: nil, description: nil }
  _decide_meta rules, req, decision_cfg

-- ── Auth config accessor ────────────────────────────────────────
-- Retourne la configuration auth chargée depuis /etc/custos/config.moon.
-- Disponible après load(). Retourne {} si load() n'a pas encore été appelé.
-- @treturn table Configuration auth (peut contenir redirect_url, captive_ip4, captive_ip6, etc.)
get_auth_cfg = ->
  auth_cfg_cache or {}

get_sni_cfg = ->
  sni_cfg_cache or {}

--- Retourne les callbacks on_response pour une règle donnée (par rule_id).
-- Utilisé par worker_responses pour le dispatch générique sans hardcode.
-- @tparam string rule_id Identifiant de règle (depuis l'entrée IPC)
-- @treturn table Liste (possiblement vide) de fonctions on_response
get_rule_on_response = (rule_id) -> _on_response_for rules, rule_id

--- Exécute le dispatch on_response (cf. filter.rule.run_on_response) sur la
-- règle identifiée par rule_id, en utilisant le jeu de règles chargé du module.
-- Noyau commun aux workers (worker_responses, doh).
-- @tparam string rule_id Identifiant de règle ayant autorisé la requête.
-- @tparam string dns_raw Réponse DNS brute (wire format) reçue de l'upstream.
-- @tparam string reason  Raison de l'autorisation (pour EDE/log).
-- @treturn table Contexte enrichi (cf. filter.rule.apply_on_response).
run_on_response = (rule_id, dns_raw, reason) -> _run_on_response rules, rule_id, dns_raw, reason

{ :load, :decide, :decide_meta, :get_auth_cfg, :get_sni_cfg, :get_rule_on_response, :run_on_response }
