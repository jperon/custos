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
{ :log_info, :log_warn } = require "log"

local rules

-- ── Chargement ────────────────────────────────────────────────────
--- Charge la configuration du filtre et compile les règles.
-- Peut être appelé à nouveau pour recharger (hot-reload).
-- @treturn nil
load = ->
  -- Invalide le cache require pour obtenir la nouvelle configuration.
  package.loaded["filter.config"] = nil
  ok, cfg = pcall require, "filter.config"
  unless ok
    log_warn { action: "filter_load_failed", err: tostring cfg }
    return
  rules = compile_rules cfg
  n = #rules
  log_info { action: "filter_loaded", rules: n }

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

{ :load, :decide, :reload }
