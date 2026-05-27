-- src/auth/worker.moon
-- Point d'entrée du worker d'authentification HTTP.
--
-- Chargé par main.moon dans un processus enfant forké.
-- Charge la configuration, charge le fichier secrets,
-- puis démarre la boucle du serveur HTTP.
--
-- Rechargement des secrets sur SIGHUP (sans redémarrage du serveur).

{ :load_secrets }      = require "auth.credentials"
{ :run }               = require "auth.server"
nft_sess               = require "auth.nft_sessions"
{ :log_info, :log_warn, :log_error, :set_action_prefix } = require "log"

ffi = require "ffi"

SIGHUP = 1

-- ── Rechargement à chaud ─────────────────────────────────────────
-- Le flag est positionné par le handler SIGHUP (signal POSIX simple
-- suffit ici : le worker auth n'est pas dans une boucle critique.

_reload_requested = false

-- ── Démarrage du worker ───────────────────────────────────────────

--- Démarre le worker d'authentification.
-- @tparam table auth_cfg Configuration auth issue de config.moon
run_auth_worker = (auth_cfg) ->
  set_action_prefix "auth_"
  log_info -> { action: "worker_start", port: auth_cfg.port }

  -- Charge le fichier secrets
  secrets_path = auth_cfg.secrets or "/etc/custos/secrets"
  secrets, err = load_secrets secrets_path
  unless secrets
    log_error -> { action: "secrets_load_failed", path: secrets_path, err: err }
    secrets = {}

  n_users = 0
  for _ in pairs secrets
    n_users += 1
  log_info -> { action: "secrets_loaded", path: secrets_path, users: n_users }

  -- Handler SIGHUP : déclenche le rechargement des secrets
  ffi.C.signal SIGHUP, ffi.cast "sighandler_t", -> _reload_requested = true

  -- Closure de rechargement passée au serveur
  reload_fn = ->
    return nil unless _reload_requested
    _reload_requested = false
    new_secrets, err2 = load_secrets secrets_path
    if new_secrets
      log_info -> { action: "secrets_reloaded", path: secrets_path }
      new_secrets
    else
      log_warn -> { action: "secrets_reload_failed", path: secrets_path, err: err2 }
      nil

  run secrets, auth_cfg, reload_fn, nft_sess, secrets_path

{ :run_auth_worker }
