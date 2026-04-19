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
{ :compile_rules, decide: _decide } = require "filter.rule"
{ :load_config } = require "filter.lib.load_config"
{ :log_info, :log_warn } = require "log"
{ :inject_localnets } = require "filter.localnets"
ip_whitelist = require "ip_whitelist"
{ :DEST_WHITELIST } = require "config"

local rules
config_path = os.getenv("CUSTOS_FILTER_CONFIG") or "/etc/custos/filter.yml"

-- ── Chemin de configuration ───────────────────────────────────────
--- Modifie le chemin vers le fichier de configuration YAML.
-- Doit être appelé avant load().
-- @tparam string path Chemin vers le fichier .yml
set_config_path = (path) ->
  config_path = path

-- ── Chargement ────────────────────────────────────────────────────
--- Charge la configuration du filtre et compile les règles.
-- Peut être appelé à nouveau pour recharger (hot-reload).
-- @treturn nil
load = ->
  cfg, err = load_config config_path
  unless cfg
    log_warn { action: "filter_load_failed", err: err }
    return
  rules = compile_rules cfg
  -- Priorité : config.DEST_WHITELIST (UCI) > cfg.dest_whitelist (filter.yml)
  whitelist = if DEST_WHITELIST and #DEST_WHITELIST > 0
    DEST_WHITELIST
  else
    cfg.dest_whitelist or {}
  
  -- Injection dynamique des réseaux locaux (Basé sur l'option allow_localnets)
  inject_localnets cfg, whitelist
  
  ip_whitelist.init whitelist
  n = #rules
  log_info { action: "filter_loaded", rules: n, dest_whitelist: #whitelist }

-- ── Décision ─────────────────────────────────────────────────────
--- Décide du verdict pour une requête DNS.
-- @tparam table req {domain, src_ip, mac, ts}
-- @treturn boolean true = autoriser, false = bloquer
-- @treturn string  Raison (pour le log)
decide = (req) ->
  unless rules
    log_warn { action: "filter_not_loaded" }
    return false, "filter not loaded"
  _decide rules, req

-- ── Rechargement SIGHUP ──────────────────────────────────────────
-- Même pattern que allowlist.moon : flag C → testé dans la boucle Q0.

reload_requested = false

sighup_handler = ffi.cast "sighandler_t", (sig) ->
  reload_requested = true

libc.signal 1, sighup_handler   -- SIGHUP = 1

--- Applique un rechargement si un SIGHUP a été reçu.
-- Doit être appelé en début de callback, avant tout traitement de paquet.
-- @treturn nil
reload = ->
  if reload_requested
    reload_requested = false
    load!

{ :load, :decide, :reload, :set_config_path }
