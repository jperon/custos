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
{ :log_info, :log_warn, :log_error } = require "log"

ffi = require "ffi"
ffi.cdef [[
  typedef void (*sighandler_t)(int);
  sighandler_t signal(int signum, sighandler_t handler);
]]

SIGHUP = 1

-- ── Rechargement à chaud ─────────────────────────────────────────
-- Le flag est positionné par le handler SIGHUP (signal POSIX simple
-- suffit ici : le worker auth n'est pas dans une boucle critique).

_reload_requested = false

-- ── Démarrage du worker ───────────────────────────────────────────

--- Démarre le worker d'authentification.
-- @tparam table auth_cfg Configuration auth issue de cfg/filter.yml
run_auth_worker = (auth_cfg) ->
  log_info { action: "auth_worker_start", port: auth_cfg.port }

  -- Charge le fichier secrets
  secrets_path = auth_cfg.secrets or "cfg/secrets"
  secrets, err = load_secrets secrets_path
  unless secrets
    log_error { action: "auth_secrets_load_failed", err: err }
    secrets = {}

  n_users = 0
  for _ in pairs secrets
    n_users += 1
  log_info { action: "auth_secrets_loaded", path: secrets_path, users: n_users }

  -- Handler SIGHUP : déclenche le rechargement des secrets
  ffi.C.signal SIGHUP, ffi.cast("sighandler_t", ->
    _reload_requested = true
  )

  -- Closure de rechargement passée au serveur
  reload_fn = ->
    return nil unless _reload_requested
    _reload_requested = false
    new_secrets, err2 = load_secrets secrets_path
    if new_secrets
      log_info { action: "auth_secrets_reloaded", path: secrets_path }
      new_secrets
    else
      log_warn { action: "auth_secrets_reload_failed", err: err2 }
      nil

  run secrets, auth_cfg, reload_fn, nft_sess, secrets_path

{ :run_auth_worker }
