-- src/auth/server.moon
-- Serveur HTTPS du portail captif.
--
-- Le worker AUTH est déjà forké par main.moon. Ce module écoute le port HTTPS
-- et fork un enfant court par connexion entrante avec lib.process, sans utiliser
-- socket.fork().
--
-- Les handlers HTTP (login/ping/logout/register/routage) sont dans auth.handlers ;
-- la gestion des sets nft d'authentification dans auth.nft_auth_sets. Ce module ne
-- garde que la machinerie réseau/TLS/fork et le replay des sessions au démarrage.

socket = require "lib.socket"
ssl = require "auth.ffi_wolfssl"
ffi = require "ffi"

{ :fork_child, :reap_one } = require "lib.process"
{ :load_sessions } = require "auth.sessions"
token = require "auth.token"
{ :load_or_generate_sni, :load_static } = require "auth.cert"
{ :extract_sni } = require "auth.sni_extractor"
{ :log_info, :log_warn, :log_error, :log_debug } = require "log"
config = require "config"
{ :read_request, :send_response } = require "lib.http"
{ :get_mac } = require "mac_learner_ipc"
{ :refresh_nft } = require "auth.nft_auth_sets"
{ :handle_request } = require "auth.handlers"

-- Repeuple les sets nftables depuis le fichier sessions au démarrage du worker.
-- Appelé une fois après init, avant le premier accept, pour que les clients
-- déjà authentifiés ne soient pas redirigés vers le portail captif après un
-- restart ou reload de custos.
replay_sessions_to_nft = (state) ->
  return unless state.nft_sess and state.sessions_file
  sessions = load_sessions state.sessions_file
  now = os.time!
  idle_timeout = (state.auth_cfg and state.auth_cfg.idle_timeout) or 120
  count = 0
  for mac, s in pairs sessions
    continue if s.expires and now > s.expires
    ttl = if s.expires then math.max 1, s.expires - now else idle_timeout
    if s.ips
      for _, ip in pairs s.ips
        refresh_nft state.nft_sess, ip, mac, ttl, s.user
    else
      state.nft_sess.add_authenticated_mac mac, ttl if mac and mac ~= "unknown"
    count += 1
  log_info -> { action: "sessions_replayed_to_nft", count: count }

--- Sélectionne le contexte TLS pour une connexion.
-- Priorité : contexte statique hérité du parent (zéro coût par connexion) >
-- repli rechargement depuis les fichiers > génération/cache SNI dynamique.
-- @tparam table state État du serveur (static_tls_ctx, static_cert_paths, cert_cache)
-- @tparam string local_ip IP locale, utilisée comme CN pour le cert dynamique
-- @tparam function|nil load_static_fn Injection de test ; défaut load_static
-- @tparam function|nil load_sni_fn Injection de test ; défaut load_or_generate_sni
-- @treturn table Contexte TLS
-- @raise string si aucun contexte ne peut être obtenu
resolve_tls_ctx = (state, local_ip, load_static_fn=load_static, load_sni_fn=load_or_generate_sni) ->
  if state.static_tls_ctx
    -- Contexte construit dans le parent et hérité via fork (COW) : pas de
    -- relecture disque ni de reconstruction par connexion.
    log_debug -> { action: "server_using_static_cert", inherited: true }
    return state.static_tls_ctx

  if state.static_cert_paths
    -- Repli : recharger depuis les fichiers si le contexte hérité manque.
    log_debug -> { action: "server_loading_static_cert_child", cert: state.static_cert_paths.cert, key: state.static_cert_paths.key }
    ctx, err = load_static_fn state.static_cert_paths.key, state.static_cert_paths.cert
    if ctx
      log_debug -> { action: "server_using_static_cert", inherited: false }
      return ctx
    log_error -> { action: "server_static_cert_load_child_failed", err: err }
    error "Cannot load static certificate in child: #{err}"

  tls_ctx = nil
  tls_ctx_ok, tls_ctx_err = pcall ->
    tls_ctx = load_sni_fn local_ip, state.cert_cache
  unless tls_ctx_ok
    log_error -> { action: "server_cert_generation_failed", local_ip: local_ip, err: tls_ctx_err }
    error "Cannot generate certificate: #{tls_ctx_err}"
  tls_ctx

handle_client = (args) ->
  client = args.client
  state = args.state
  peer_ip = args.peer_ip or "unknown"

  ok, err = pcall ->
    log_debug -> { action: "server_handle_client_start", peer: peer_ip, fd: client.fd }

    -- Obtenir l'IP locale du socket (sur laquelle le client s'est connecté)
    local_ip = client\getsockname!
    unless local_ip
      errno = tonumber(ffi.C.__errno_location()[0])
      log_warn -> { action: "server_getsockname_failed", peer: peer_ip, errno: errno }
      local_ip = "custos"  -- Fallback

    log_debug -> { action: "server_local_ip_detected", local_ip: local_ip }

    -- Utiliser le certificat statique s'il a été configuré
    -- Sinon, générer/charger le certificat avec l'IP locale comme CN
    tls_ctx = resolve_tls_ctx state, local_ip

    unless tls_ctx
      log_error -> { action: "server_cert_null", local_ip: local_ip }
      error "Certificate context is nil"

    log_debug -> { action: "server_cert_loaded", local_ip: local_ip }

    -- Set socket to BLOCKING mode for handshake
    log_debug -> { action: "server_set_blocking_mode" }
    client\settimeout nil  -- nil = blocking mode
    -- … mais avec une échéance noyau (SO_RCVTIMEO/SO_SNDTIMEO) : sans elle,
    -- une connexion muette (préconnexion spéculative de Firefox, client
    -- disparu) suspend l'enfant AUTH-conn pour toujours. Côté navigateur, ces
    -- sockets zombies saturent la limite de connexions par hôte et retardent
    -- les pings suivants (~70 s de "blocked" observés en HAR).
    client_timeout = (state.auth_cfg and tonumber state.auth_cfg.client_timeout) or 15
    pcall -> client\setoption "rcvtimeo", client_timeout
    pcall -> client\setoption "sndtimeo", client_timeout
    log_debug -> { action: "server_blocking_mode_set", client_timeout: client_timeout }

    log_debug -> { action: "server_ssl_wrap_start" }
    tls_client, tls_err = ssl.wrap client, tls_ctx
    log_debug -> { action: "server_ssl_wrap_done" }

    unless tls_client
      log_warn -> { action: "server_tls_wrap_failed", peer: peer_ip, err: tls_err }
      client\close!
      return

    log_debug -> { action: "server_dohandshake_start" }

    -- Handshake loop: keep trying until complete or error
    handshake_complete = false
    handshake_attempts = 0
    -- Échéance absolue : avec SO_RCVTIMEO, chaque tentative WANT_READ peut
    -- bloquer jusqu'à client_timeout ; sans deadline, 50 tentatives sur une
    -- connexion muette tiendraient l'enfant des minutes.
    handshake_deadline = os.time! + client_timeout
    while not handshake_complete and handshake_attempts < 50 and os.time! <= handshake_deadline
      handshake_attempts += 1
      log_debug -> { action: "server_handshake_attempt", attempt: handshake_attempts }

      ok_hs, hs_err = tls_client\dohandshake!
      log_debug -> { action: "server_dohandshake_returned", ok: ok_hs }

      if ok_hs
        log_debug -> { action: "server_handshake_complete" }
        handshake_complete = true
      elseif hs_err and hs_err != "peer_closed"
        break  -- erreur fatale (tls_error) : inutile de réessayer

    unless handshake_complete
      if hs_err == "peer_closed"
        log_warn -> { action: "server_tls_handshake_peer_closed", peer: peer_ip, attempts: handshake_attempts }
      else
        log_warn -> { action: "server_tls_handshake_failed", peer: peer_ip, attempts: handshake_attempts, err: hs_err or "max attempts reached" }
      tls_client\close!
      return

    -- After handshake, socket is still blocking (nil timeout)
    -- Leave it blocking for HTTP I/O (client must send request promptly)
    log_debug -> { action: "server_set_http_timeout" }

    peer_mac = get_mac peer_ip
    req, req_err = read_request tls_client, timeout: client_timeout
    unless req
      log_warn -> { action: "server_request_read_failed", peer: peer_ip, err: req_err }
      tls_client\close!
      return

    status, headers, body = handle_request req, peer_ip, peer_mac, state
    send_response tls_client, status, headers, body
    tls_client\close!

  unless ok
    log_error -> { action: "server_client_failed", peer: peer_ip, err: tostring err }
    pcall -> client\close!

--- Fork un enfant pour traiter une connexion acceptée, sans jamais propager
-- d'erreur. Un échec transitoire de fork() (EAGAIN/ENOMEM sur routeur à faible
-- RAM) est isolé : la connexion est fermée et le serveur continue. Sans cette
-- garde, l'error() remontée par fork_child ferait crasher le worker AUTH (toutes
-- les connexions refusées jusqu'au redémarrage par le superviseur).
-- @tparam table client Socket client accepté (fermé dans tous les cas)
-- @tparam string peer_ip IP du pair (pour les logs)
-- @tparam table state État du serveur transmis à handle_client
-- @tparam function|nil fork_fn Injection de test ; défaut fork_child
-- @treturn boolean true si le fork a réussi
dispatch_connection = (client, peer_ip, state, fork_fn=fork_child) ->
  log_debug -> { action: "server_fork_child_start", peer: peer_ip, fd: client.fd }
  fork_ok, pid = pcall fork_fn, "AUTH-conn",
    handle_client,
    { client: client, peer_ip: peer_ip, state: state },
    { log_start: false }

  if fork_ok
    log_debug -> { action: "server_fork_child_done", pid: pid }
    log_info -> { action: "server_conn_started", pid: pid, peer: peer_ip }
  else
    log_error -> { action: "server_fork_child_failed", peer: peer_ip, err: tostring pid }

  pcall -> client\close!
  fork_ok

reload_secrets_if_needed = (state) ->
  return unless state.reload_fn
  new_secrets = state.reload_fn!
  state.secrets = new_secrets if new_secrets

--- Crée un socket serveur TCP IPv4.
-- @tparam number port Port d'écoute
-- @treturn table|nil Socket serveur, ou nil + message d'erreur
make_server4 = (port) ->
  srv = socket.tcp!
  ok, err = srv\bind "0.0.0.0", port
  unless ok
    srv\close!
    return nil, err
  srv\listen 32
  srv\settimeout 1
  srv

--- Crée un socket serveur TCP IPv6 (non fatal si non disponible).
-- @tparam number port Port d'écoute
-- @treturn table|nil Socket serveur, ou nil si IPv6 indisponible
make_server6 = (port) ->
  ok6, srv6 = pcall socket.tcp6
  return nil unless ok6 and srv6
  srv6\setoption "ipv6-v6only", true
  ok62, _ = pcall srv6.bind, srv6, "::", port
  unless ok62
    srv6\close!
    return nil
  srv6\listen 32
  srv6\settimeout 1
  srv6

--- Démarre le serveur HTTPS d'authentification.
-- @tparam table secrets Table des secrets déjà chargée
-- @tparam table auth_cfg Configuration auth
-- @tparam function reload_fn Fonction optionnelle de rechargement des secrets
-- @tparam table nft_sess Module auth.nft_sessions
-- @tparam string secrets_path Chemin du fichier secrets
-- @treturn nil
run = (secrets, auth_cfg, reload_fn, nft_sess, secrets_path) ->
  port = auth_cfg.port or 33443
  sessions_file = auth_cfg.sessions_file or config.auth.sessions_file

  log_debug -> { action: "server_startup", port: port }
  log_debug -> { action: "server_auth_cfg_received", cert: auth_cfg.cert, key: auth_cfg.key }

  -- Initialiser le cache de certificats (persistant, 90 jours TTL)
  log_debug -> { action: "server_cert_cache_init" }
  cert_cache_module = require "auth.cert_cache"
  cert_cache = cert_cache_module.create_cache 500, 7776000  -- 500 certs, 90 days TTL

  -- Charger le certificat statique s'il est fourni dans la configuration.
  -- load_static retourne (ctx, err) : récupérer le contexte dans `ctx`, pas `ok`
  -- (l'inversion historique mettait static_tls_ctx à nil, d'où le contournement
  -- coûteux qui rechargeait le cert dans chaque enfant).
  -- Le contexte est construit une seule fois et réutilisé par les enfants : le
  -- fork() copie l'espace d'adressage (COW), et un WOLFSSL_CTX (cert/clé en
  -- mémoire, sans descripteur) est partageable entre objets SSL.
  static_tls_ctx = nil
  if auth_cfg.cert and auth_cfg.key
    log_info -> { action: "server_loading_static_cert", cert: auth_cfg.cert, key: auth_cfg.key }
    ctx, cert_err = load_static auth_cfg.key, auth_cfg.cert
    if ctx
      static_tls_ctx = ctx
      log_info -> { action: "server_static_cert_loaded", cert: auth_cfg.cert, key: auth_cfg.key }
    else
      log_warn -> { action: "server_static_cert_failed", cert: auth_cfg.cert, key: auth_cfg.key, err: cert_err }
  else
    log_debug -> { action: "server_no_static_cert_configured" }

  token_key = token.load_key auth_cfg.session_key or "/etc/custos/session.key"
  log_info -> { action: "server_session_key_loaded" }

  listen4, err4 = make_server4 port
  error "Impossible de démarrer le serveur IPv4 sur port #{port} : #{err4}" unless listen4
  listen6 = make_server6 port

  all_servers = { listen4 }
  all_servers[#all_servers + 1] = listen6 if listen6

  state = {
    secrets: secrets or {}
    auth_cfg: auth_cfg
    reload_fn: reload_fn
    nft_sess: nft_sess
    secrets_path: secrets_path
    sessions_file: sessions_file
    token_key: token_key
    admin_users: auth_cfg.admin_users or {}
    admin_allow_all_when_empty: auth_cfg.admin_allow_all_when_empty or false
    config_path: auth_cfg.config_path or "/etc/custos/config.moon"
    started_at: os.time!
    -- Contexte TLS statique construit une fois, hérité par les enfants via fork.
    static_tls_ctx: static_tls_ctx
    -- Chemins conservés en repli si le contexte hérité est absent.
    static_cert_paths: if auth_cfg.cert and auth_cfg.key then { cert: auth_cfg.cert, key: auth_cfg.key } else nil
    cert_cache: cert_cache
  }

  log_info -> {
    action: "server_listening"
    port: port
    ipv4: "0.0.0.0"
    ipv6: listen6 and "::" or nil
    sessions_file: sessions_file
    cert_cache: if auth_cfg.cert and auth_cfg.key then "static cert + dynamic SNI cache" else "dynamic SNI cache (500 slots, 90d TTL)"
  }

  replay_sessions_to_nft state

  while true
    reload_secrets_if_needed state

    while true
      dead_pid = reap_one!
      break unless dead_pid and dead_pid > 0

    readable, _ = socket.select all_servers, nil, 0.1
    if readable
      for srv in *readable
        log_debug -> { action: "server_socket_select_readable" }
        client = srv\accept!
        log_debug -> { action: "server_accept_returned" }

        if client
          log_debug -> { action: "server_got_client" }
          peer_ip = client\getpeername! or "unknown"
          log_debug -> { action: "server_getpeername_result", peer: peer_ip }

          dispatch_connection client, peer_ip, state

{ :run, :replay_sessions_to_nft, :dispatch_connection, :resolve_tls_ctx }
