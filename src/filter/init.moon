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
{ :compile_rules, decide: _decide, decide_meta: _decide_meta } = require "filter.rule"
{ :log_info, :log_warn } = require "log"
{ :inject_localnets } = require "filter.localnets"
ip_whitelist = require "ip_whitelist"
config = require "config"

local rules
local auth_cfg_cache
local decision_cfg

clone = (v) ->
  return v unless type(v) == "table"
  out = {}
  for k, item in pairs v
    out[k] = clone item
  out

build_filter_cfg = ->
  root = config.filter or {}
  cfg = clone root
  cfg.nets = cfg.nets or {}
  cfg.macs = cfg.macs or {}
  cfg.times = cfg.times or {}
  cfg.sources = cfg.sources or {}
  cfg.rules = cfg.rules or {}
  cfg.users = cfg.users or {}
  cfg.dest_whitelist = cfg.dest_whitelist or {}
  cfg.allowed_domains = cfg.allowed_domains or {}
  cfg.auth = clone(config.auth or {})

  -- Transition minimale: si aucune règle n'est fournie, on génère
  -- "allow allowed_domains" puis "deny default".
  if #cfg.rules == 0 and #cfg.allowed_domains > 0
    cfg.rules = {
      {
        description: "Builtin allowlist domains"
        actions: { "allow" }
        conditions: {
          { to_domains: clone cfg.allowed_domains }
        }
      }
      {
        description: "Builtin default deny"
        actions: { "deny" }
      }
    }

  cfg

-- ── Chargement ────────────────────────────────────────────────────
--- Charge la configuration du filtre depuis /etc/config.moon.
-- Peut être appelé à nouveau pour recharger (hot-reload).
-- @treturn nil
load = ->
  cfg = build_filter_cfg!
  unless cfg
    log_warn { action: "filter_load_failed", err: "invalid runtime config" }
    return
  rules = compile_rules cfg
  auth_cfg_cache = cfg.auth
  decision_cfg = cfg.decision or {}
  whitelist = cfg.dest_whitelist or {}

  -- Injection dynamique des réseaux locaux (Basé sur l'option allow_localnets)
  inject_localnets cfg, whitelist

  ip_whitelist.init whitelist
  -- NFT extra rules are applied once at process startup by worker_questions
  -- (moved out of filter.load to avoid re-inserting rules on hot-reload)
  n = #rules
  log_info { action: "filter_loaded", rules: n, dest_whitelist: #whitelist }

-- ── Décision ─────────────────────────────────────────────────────
--- Décide du verdict pour une requête DNS.
-- @tparam table req {domain, src_ip, mac, ts}
-- @treturn boolean true = autoriser, false = bloquer
-- @treturn string  Raison (pour le log)
-- @treturn string  Description de la règle ayant matché (pour le log)
decide = (req) ->
  unless rules
    log_warn { action: "filter_not_loaded", domain: req and req.domain or "unknown" }
    return false, "filter not loaded", nil
  _decide rules, req, decision_cfg

decide_meta = (req) ->
  unless rules
    log_warn { action: "filter_not_loaded", domain: req and req.domain or "unknown" }
    return {
      verdict: false
      reason: "filter not loaded"
      rule_id: nil
      timeout: nil
      description: nil
    }
  _decide_meta rules, req, decision_cfg

-- ── Auth config accessor ────────────────────────────────────────
-- Retourne la configuration auth chargée depuis /etc/config.moon.
-- Disponible après load(). Retourne {} si load() n'a pas encore été appelé.
-- @treturn table Configuration auth (peut contenir redirect_url, captive_ip4, captive_ip6, etc.)
get_auth_cfg = ->
  auth_cfg_cache or {}

{ :load, :decide, :decide_meta, :get_auth_cfg }
