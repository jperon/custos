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
{ :create_watcher }    = require "lib.sighup"

-- ── Rechargement à chaud ─────────────────────────────────────────
-- SIGHUP est bloqué et lu par signalfd depuis la boucle du serveur
-- (lib/sighup.moon) : aucun handler C asynchrone, donc aucun callback FFI
-- susceptible d'être appelé pendant du code JIT (« bad callback », cf.
-- lj_ccallback.c:726-730).

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

  -- Veille SIGHUP : le signal est masqué et le fd ouvert avant la boucle.
  -- Un échec n'est pas fatal : le worker sert alors sans rechargement à chaud.
  watcher_ok, watcher = pcall create_watcher
  unless watcher_ok
    log_error -> { action: "sighup_watch_failed", err: tostring watcher }
    watcher = nil

  -- Closure de rechargement passée au serveur : interroge le signalfd à
  -- chaque tour de boucle (latence bornée par le timeout de socket.select).
  reload_fn = ->
    return nil unless watcher and watcher\pending!
    new_secrets, err2 = load_secrets secrets_path
    if new_secrets
      log_info -> { action: "secrets_reloaded", path: secrets_path }
      new_secrets
    else
      log_warn -> { action: "secrets_reload_failed", path: secrets_path, err: err2 }
      nil

  run secrets, auth_cfg, reload_fn, nft_sess, secrets_path

{ :run_auth_worker }
