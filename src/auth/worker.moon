-- src/auth/worker.moon
-- Point d'entrée du worker d'authentification HTTPS.
--
-- Chargé par main.moon dans un processus enfant forké.
-- Charge la configuration, génère ou charge le certificat TLS,
-- charge le fichier secrets, puis démarre la boucle du serveur HTTPS.
--
-- Rechargement des secrets sur SIGHUP (sans redémarrage du serveur).

{ :load_or_generate }  = require "auth.cert"
{ :load_secrets }      = require "auth.credentials"
{ :run }               = require "auth.server"
nft_sess               = require "auth.nft_sessions"
captive                = require "auth.captive"
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
  -- Chemins du certificat et de la clé
  cert_path = auth_cfg.cert or "./tmp/auth.crt"
  key_path  = auth_cfg.key  or "./tmp/auth.key"

  log_info { action: "auth_worker_start", port: auth_cfg.port }

  -- Charge ou génère le certificat TLS
  tls_ctx = load_or_generate key_path, cert_path
  log_info { action: "auth_cert_loaded", cert: cert_path }

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

  -- Portail captif : sockets HTTP plain (si captive_port configuré)
  captive_srvs = {}
  captive_port = auth_cfg.captive_port
  if captive_port and captive_port > 0
    log_info { action: "captive_portal_start", port: captive_port }
    cap4, err_c4 = captive.make_captive4 captive_port
    if cap4
      captive_srvs[#captive_srvs + 1] = cap4
    else
      log_warn { action: "captive_portal_ipv4_failed", err: err_c4 }
    cap6 = captive.make_captive6 captive_port
    if cap6
      captive_srvs[#captive_srvs + 1] = cap6
    else
      log_info { action: "captive_portal_ipv6_skipped" }

  run tls_ctx, secrets, auth_cfg, reload_fn, nft_sess, captive_srvs, secrets_path

{ :run_auth_worker }
