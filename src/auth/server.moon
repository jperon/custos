-- src/auth/server.moon
-- Serveur HTTPS du portail captif.
--
-- Le worker AUTH est déjà forké par main.moon. Ce module écoute le port HTTPS
-- et fork un enfant court par connexion entrante avec lib.process, sans utiliser
-- socket.fork().

socket = require "lib.socket"
ssl = require "auth.ffi_wolfssl"
ffi = require "ffi"

{ :fork_child, :reap_one } = require "lib.process"
{ :session_for_mac, :add_session, :purge_expired, :load_sessions, :write_sessions } = require "auth.sessions"
{ :verify_password, :register_user, :update_user_hash } = require "auth.credentials"
token = require "auth.token"
{ :load_or_generate_sni, :load_static } = require "auth.cert"
{ :extract_sni } = require "auth.sni_extractor"
{ :log_info, :log_warn, :log_error, :log_debug } = require "log"
config = require "config"
{ :read_request, :send_response } = require "lib.http"
{ :user_qualifies_for_rule } = require "auth.rule_user"

{ :get_mac } = require "mac_learner_ipc"

ffi.cdef [[
  typedef int pid_t;
  pid_t getppid(void);
  int kill(pid_t pid, int sig);
]]


{ :page, :success_page, :css_content } = require "auth.pages"

SIGHUP = 1

COOKIE_NAME = "custos_session"

make_session_cookie = (tok) ->
  "#{COOKIE_NAME}=#{tok}; Path=/; HttpOnly; SameSite=Strict"

clear_session_cookie = ->
  "#{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"

signal_parent_reload = ->
  parent_pid = tonumber ffi.C.getppid!
  return false if parent_pid <= 0
  rc = ffi.C.kill parent_pid, SIGHUP
  rc == 0

H = require "auth.html"

url_decode = (s) ->
  return "" unless s
  s = s\gsub "+", " "
  s\gsub "%%(%x%x)", (hex) -> string.char tonumber hex, 16

parse_form = (body) ->
  out = {}
  return out unless body
  for k, v in body\gmatch "([^&=]+)=([^&]*)"
    out[url_decode k] = url_decode v
  out

register_form_page = (req) ->
  page {
    H.form { method: "POST", action: "/register" },
      H.label "Utilisateur ", H.input({ name: "user", type: "text" }), H.br!,
      H.label "Mot de passe ", H.input({ name: "password", type: "password" }), H.br!,
      H.button { type: "submit" }, "S'inscrire"
    H.a { href: "/" }, "Déjà un compte ? Se connecter"
  }

register_success_page = (req) ->
  page {
    H.p "Compte créé. Vous pouvez maintenant vous connecter.",
    H.a { href: "/" }, "Se connecter"
  }

login_page = ->
  page {
    H.form { method: "POST", action: "/login" },
      H.label "Utilisateur ", H.input({ name: "user", type: "text" }), H.br!,
      H.label "Mot de passe ", H.input({ name: "password", type: "password" }), H.br!,
      H.button { type: "submit" }, "Connexion"
    H.a { href: "/register" }, "Inscription"
  }


-- Generate stable rule_id matching compiler_api.rule_id_base
sanitize_id = (raw) ->
  s = tostring(raw)\lower!
  s = s\gsub "[^a-z0-9_%-]+", "_"
  s = s\gsub "_+", "_"
  s = s\gsub "^_+", ""
  s = s\gsub "_+$", ""
  s = s\gsub "%-+", "_"
  if #s > 40
    s = s\sub 1, 40
  s

rule_id = require "filter.rule_id"

generate_rule_id = rule_id.generate

-- Check if a rule requires authentication (has from_users or from_userlists condition)
rule_requires_auth = (rule) ->
  return false unless rule and rule.conditions
  conditions = rule.conditions
  -- If conditions is a table with numeric keys, it's an array (old format)
  -- If conditions is a table with string keys, it's a table (new format with implicit AND)
  is_array_format = type(conditions[1]) == "table"

  if is_array_format
    -- Old format: array of conditions
    for _, cond in ipairs conditions
      continue unless type(cond) == "table"
      for k, _ in pairs cond
        if k == "from_users" or k == "from_userlists"
          return true
  else
    -- New format: table of conditions (implicit AND)
    for k, _ in pairs conditions
      if k == "from_users" or k == "from_userlists"
        return true
  false

-- Wrapper lisant userlists depuis la config live, délègue à auth.rule_user
qualifies_for_rule = (user, rule) ->
  filter_cfg = config.filter or {}
  user_qualifies_for_rule user, rule, filter_cfg.userlists or {}

-- Refresh nft sets for authenticated user (called by ping and login)
refresh_nft = (nft_sess, ip, mac, ttl, user) ->
  return unless nft_sess
  nft_sess.add_authenticated ip, ttl if ip and ip ~= "unknown"
  nft_sess.add_authenticated_mac mac, ttl if mac and mac ~= "unknown"

  -- Populate per-rule auth sets for rules requiring authentication
  filter_cfg = config.filter or {}
  rules = filter_cfg.rules or {}
  for idx, rule in ipairs rules
    requires_auth = rule_requires_auth rule
    continue unless requires_auth
    qualifies = qualifies_for_rule user, rule
    continue unless qualifies

    -- Generate stable rule_id
    rule_id = generate_rule_id rule, idx

    -- Populate auth sets directly via nft_sessions.run_nft()
    ok, err = pcall ->
      if nft_sess
        nft_sess.run_nft "add element bridge dns-filter-bridge #{rule_id}_auth_mac { #{mac} timeout #{ttl}s }", { quiet: true }
        if ip and ip ~= "unknown"
          if ip\find ":"
            nft_sess.run_nft "add element bridge dns-filter-bridge #{rule_id}_auth_ip6 { #{ip} timeout #{ttl}s }", { quiet: true }
          else
            nft_sess.run_nft "add element bridge dns-filter-bridge #{rule_id}_auth_ip4 { #{ip} timeout #{ttl}s }", { quiet: true }
    unless ok
      log_warn -> { action: "auth_set_add_failed", rule_id: rule_id, mac: mac, ip: ip, err: tostring(err) }

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

handle_login = (req, peer_ip, peer_mac, state) ->
  form = parse_form req.body
  user = form.user
  pass = form.password

  unless user and pass
    return 400, {}, "Missing credentials"

  stored = state.secrets and state.secrets[user]
  unless stored
    return 401, {}, "Invalid credentials"
  ok, needs_rehash = verify_password pass, stored
  unless ok
    return 401, {}, "Invalid credentials"

  -- Migrate hash to current DEFAULT_ITER if needed (transparent to the user).
  if needs_rehash and state.secrets_path
    rh_ok, rh_err = update_user_hash user, pass, state.secrets_path
    if rh_ok
      log_info -> { action: "credentials_rehashed", user: user }
    else
      log_warn -> { action: "credentials_rehash_failed", user: user, err: tostring rh_err }

  sessions = load_sessions state.sessions_file
  purge_expired sessions

  -- Utiliser directement la MAC fournie par le worker NFQUEUE
  mac = peer_mac

  unless mac and mac ~= "unknown"
    log_warn -> { action: "server_login_mac_missing", ip: peer_ip, mac: mac }
    return 401, {}, "Unable to identify client MAC (IP: #{peer_ip})"

  log_info -> { action: "server_login_success", user: user, mac: mac, ip: peer_ip }

  idle_timeout = state.auth_cfg.idle_timeout or 120
  now = os.time!
  add_session sessions, mac, peer_ip, user, now + idle_timeout
  ok, err = write_sessions sessions, state.sessions_file
  unless ok
    log_warn -> { action: "server_sessions_write_failed", path: state.sessions_file, err: err }
    return 500, {}, "Session persistence failed"
  log_info -> { action: "server_sessions_write_success", path: state.sessions_file, mac: mac }

  if state.nft_sess
    ok, err = pcall -> refresh_nft state.nft_sess, peer_ip, mac, state.auth_cfg.idle_timeout, user
    unless ok
      log_warn -> { action: "server_nft_refresh_failed", peer: peer_ip, mac: mac, err: tostring(err) }
  else
    log_warn -> { action: "server_nft_sess_missing", peer: peer_ip, mac: mac }

  -- Populate per-rule auth sets for rules requiring authentication
  filter_cfg = config.filter or {}
  rules = filter_cfg.rules or {}
  for idx, rule in ipairs rules
    requires_auth = rule_requires_auth rule
    qualifies = qualifies_for_rule user, rule
    log_info -> { action: "server_rule_check", idx: idx, description: rule.description, requires_auth: requires_auth, qualifies: qualifies, user: user }
    continue unless requires_auth
    continue unless qualifies

    -- Generate stable rule_id
    rule_id = generate_rule_id rule, idx
    log_info -> { action: "server_rule_id_generated", rule_id: rule_id, description: rule.description }

    -- Populate auth sets directly via nft_sessions.run_nft()
    ok, err = pcall ->
      if state.nft_sess
        state.nft_sess.run_nft "add element bridge dns-filter-bridge #{rule_id}_auth_mac { #{mac} timeout #{state.auth_cfg.idle_timeout}s }", { quiet: true }
        log_info -> { action: "server_auth_set_add_mac", rule_id: rule_id, mac: mac }
        if peer_ip and peer_ip ~= "unknown"
          if peer_ip\find ":"
            state.nft_sess.run_nft "add element bridge dns-filter-bridge #{rule_id}_auth_ip6 { #{peer_ip} timeout #{state.auth_cfg.idle_timeout}s }", { quiet: true }
            log_info -> { action: "server_auth_set_add_ip6", rule_id: rule_id, ip: peer_ip }
          else
            state.nft_sess.run_nft "add element bridge dns-filter-bridge #{rule_id}_auth_ip4 { #{peer_ip} timeout #{state.auth_cfg.idle_timeout}s }", { quiet: true }
            log_info -> { action: "server_auth_set_add_ip4", rule_id: rule_id, ip: peer_ip }
    unless ok
      log_warn -> { action: "server_auth_set_add_failed", rule_id: rule_id, mac: mac, ip: peer_ip, err: tostring(err) }

  tok = token.generate "user", user, mac, now + idle_timeout, state.token_key
  admin_users = state.admin_users or {}
  user_in_admin = false
  for _, u in ipairs admin_users
    user_in_admin = true if u == user
  is_admin = (state.admin_allow_all_when_empty and #admin_users == 0) or user_in_admin
  200, {
    ["Content-Type"]: "text/html; charset=UTF-8"
    ["Set-Cookie"]: make_session_cookie tok
  }, success_page state.auth_cfg, now, is_admin

handle_ping = (req, peer_ip, peer_mac, state) ->
  log_info -> { action: "server_ping_received", peer_ip: peer_ip, peer_mac: peer_mac }

  cookie_val = token.get_cookie req.headers.cookie or "", COOKIE_NAME
  p, tok_err = token.verify cookie_val, state.token_key
  unless p
    log_info -> { action: "server_ping_token_invalid", peer_ip: peer_ip, err: tok_err }
    return 401, {}, ""

  user = p.user
  mac  = p.mac
  idle_timeout = state.auth_cfg.idle_timeout or 120
  now  = os.time!
  new_expires = now + idle_timeout

  sessions = load_sessions state.sessions_file
  purge_expired sessions

  -- Rejeter si la session a été explicitement invalidée (logout).
  -- Un token encore cryptographiquement valide ne doit pas recréer une session détruite.
  if mac and mac ~= "unknown" and not sessions[mac\lower!]
    log_info -> { action: "server_ping_session_invalidated", peer_ip: peer_ip, mac: mac }
    return 401, {}, ""

  add_session sessions, mac, peer_ip, user, new_expires
  write_sessions sessions, state.sessions_file

  refresh_nft state.nft_sess, peer_ip, mac, idle_timeout, user

  new_tok = token.generate "user", user, mac, new_expires, state.token_key
  log_info -> { action: "server_ping_success", peer_mac: mac }
  204, { ["Set-Cookie"]: make_session_cookie new_tok }, ""

handle_logout = (req, peer_ip, peer_mac, state) ->
  cookie_val = token.get_cookie req.headers.cookie or "", COOKIE_NAME
  p = (token.verify cookie_val, state.token_key)
  mac  = (p and p.mac) or peer_mac
  user = p and p.user

  if mac and mac ~= "unknown"
    sessions = load_sessions state.sessions_file
    sessions[mac\lower!] = nil
    write_sessions sessions, state.sessions_file

  if state.nft_sess
    state.nft_sess.del_authenticated peer_ip
    state.nft_sess.del_authenticated_mac mac if mac and mac ~= "unknown"

  if user and state.nft_sess
    filter_cfg = config.filter or {}
    rules = filter_cfg.rules or {}
    for idx, rule in ipairs rules
      continue unless rule_requires_auth rule
      continue unless qualifies_for_rule user, rule
      rule_id = generate_rule_id rule, idx
      ok, err = pcall ->
        state.nft_sess.run_nft "delete element bridge dns-filter-bridge #{rule_id}_auth_mac { #{mac} }", { quiet: true }
        if peer_ip and peer_ip ~= "unknown"
          if peer_ip\find ":"
            state.nft_sess.run_nft "delete element bridge dns-filter-bridge #{rule_id}_auth_ip6 { #{peer_ip} }", { quiet: true }
          else
            state.nft_sess.run_nft "delete element bridge dns-filter-bridge #{rule_id}_auth_ip4 { #{peer_ip} }", { quiet: true }
      log_warn -> { action: "server_auth_set_delete_failed", rule_id: rule_id, mac: mac, ip: peer_ip, err: tostring(err) } unless ok

  302, { ["Location"]: "/", ["Set-Cookie"]: clear_session_cookie! }, ""

handle_register = (req, peer_ip, peer_mac, state) ->
  form = parse_form req.body
  user = form.user
  pass = form.password

  unless user and pass
    return 400, {}, "Missing credentials"

  new_secrets, err = register_user user, pass, state.secrets_path, state.secrets
  unless new_secrets
    if err and err\match "déjà"
      return 409, {}, err
    return 500, {}, err or "Registration failed"

  state.secrets = new_secrets
  if not signal_parent_reload!
    log_warn -> { action: "server_reload_signal_failed", parent_pid: tonumber(ffi.C.getppid!) }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, register_success_page req

handle_request = (req, peer_ip, peer_mac, state) ->
  log_info -> { action: "server_request_received", path: req.path, method: req.method, peer_ip: peer_ip, peer_mac: peer_mac }
  if req.path == "/" and req.method == "GET"
    return 200, { ["Content-Type"]: "text/html; charset=UTF-8" }, login_page!
  elseif req.path == "/css" and req.method == "GET"
    return 200, { ["Content-Type"]: "text/css" }, css_content
  elseif req.path == "/login" and req.method == "POST"
    log_info -> { action: "server_routing_to_handle_login", path: req.path, method: req.method }
    return handle_login req, peer_ip, peer_mac, state
  elseif req.path == "/ping" and req.method == "GET"
    return handle_ping req, peer_ip, peer_mac, state
  elseif req.path == "/logout"
    return handle_logout req, peer_ip, peer_mac, state
  elseif req.path == "/register" and req.method == "GET"
    return 200, { ["Content-Type"]: "text/html; charset=UTF-8" }, register_form_page req
  elseif req.path == "/register" and req.method == "POST"
    return handle_register req, peer_ip, peer_mac, state
  elseif req.path\match "^/admin"
    webui_router = require "webui.router"
    return webui_router.dispatch req, state
  else
    return 302, { ["Location"]: "/" }, ""

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
    tls_ctx = nil
    if state.static_cert_paths
      log_debug -> { action: "server_loading_static_cert_child", cert: state.static_cert_paths.cert, key: state.static_cert_paths.key }
      ctx, err = load_static state.static_cert_paths.key, state.static_cert_paths.cert
      if ctx
        tls_ctx = ctx
        log_debug -> { action: "server_using_static_cert" }
      else
        log_error -> { action: "server_static_cert_load_child_failed", err: err }
        error "Cannot load static certificate in child: #{err}"
    else
      tls_ctx_ok, tls_ctx_err = pcall ->
        tls_ctx = load_or_generate_sni local_ip, state.cert_cache
      unless tls_ctx_ok
        log_error -> { action: "server_cert_generation_failed", local_ip: local_ip, err: tls_ctx_err }
        error "Cannot generate certificate: #{tls_ctx_err}"

    unless tls_ctx
      log_error -> { action: "server_cert_null", local_ip: local_ip }
      error "Certificate context is nil"

    log_debug -> { action: "server_cert_loaded", local_ip: local_ip }

    -- Set socket to BLOCKING mode for handshake
    log_debug -> { action: "server_set_blocking_mode" }
    client\settimeout nil  -- nil = blocking mode
    log_debug -> { action: "server_blocking_mode_set" }

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
    while not handshake_complete and handshake_attempts < 50
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
    req, req_err = read_request tls_client
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

  -- Charger le certificat statique s'il est fourni dans la configuration
  static_tls_ctx = nil
  if auth_cfg.cert and auth_cfg.key
    log_info -> { action: "server_loading_static_cert", cert: auth_cfg.cert, key: auth_cfg.key }
    ok, ctx = load_static auth_cfg.key, auth_cfg.cert
    if ok
      static_tls_ctx = ctx
      log_info -> { action: "server_static_cert_loaded", cert: auth_cfg.cert, key: auth_cfg.key }
    else
      log_warn -> { action: "server_static_cert_failed", cert: auth_cfg.cert, key: auth_cfg.key, err: ctx }
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

          log_debug -> { action: "server_fork_child_start", peer: peer_ip, fd: client.fd }
          pid = fork_child "AUTH-conn",
            handle_client,
            { client: client, peer_ip: peer_ip, state: state },
            { log_start: false }

          log_debug -> { action: "server_fork_child_done", pid: pid }

          log_info -> { action: "server_conn_started", pid: pid, peer: peer_ip }
          client\close!

{ :run, :replay_sessions_to_nft }
