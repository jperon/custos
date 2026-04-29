-- src/auth/server.moon
-- Serveur HTTPS du portail captif.
--
-- Le worker AUTH est déjà forké par main.moon. Ce module écoute le port HTTPS
-- et fork un enfant court par connexion entrante avec lib.process, sans utiliser
-- socket.fork().

socket = require "socket"
ssl = require "ssl"

{ :fork_child, :reap_one } = require "lib.process"
{ :session_for_mac, :add_session, :purge_expired, :load_sessions, :write_sessions } = require "auth.sessions"
{ :verify_password, :register_user } = require "auth.credentials"
{ :load_or_generate } = require "auth.cert"
{ :log_info, :log_warn, :log_error } = require "log"
{ :AUTH_SESSIONS_FILE } = require "config"

{ :get_mac } = require "mac_learner_ipc"

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

read_request = (client) ->
  request_line, err = client\receive "*l"
  return nil, err unless request_line

  method, path = request_line\match "^(%w+)%s+([^%s]+)%s+HTTP"
  return nil, "bad_request_line" unless method and path

  headers = {}
  content_length = 0

  while true
    line, line_err = client\receive "*l"
    return nil, line_err unless line
    break if line == ""

    name, value = line\match "^([^:]+):%s*(.*)$"
    if name
      lname = name\lower!
      headers[lname] = value
      if lname == "content-length"
        content_length = tonumber(value) or 0

  body = ""
  if content_length > 0
    body = client\receive content_length
    body = body or ""

  {
    method: method
    path: path
    headers: headers
    body: body
  }

send_response = (client, status, headers, body) ->
  body or= ""
  reason = switch status
    when 200 then "OK"
    when 204 then "No Content"
    when 302 then "Found"
    when 400 then "Bad Request"
    when 401 then "Unauthorized"
    when 404 then "Not Found"
    when 409 then "Conflict"
    else "Internal Server Error"

  headers or= {}
  headers["Content-Length"] = tostring #body unless headers["Content-Length"]
  headers["Connection"] = "close" unless headers["Connection"]

  client\send "HTTP/1.1 #{status} #{reason}\r\n"
  for name, value in pairs headers
    client\send "#{name}: #{value}\r\n"
  client\send "\r\n"
  client\send body if #body > 0

page = =>
  "<!DOCTYPE html>\n" .. H.html {lang: "fr",
    H.head {
      H.meta charset: "UTF-8",
      H.title "CustosVirginum",
      H.link rel: "stylesheet", href: "/css"
      H.link rel: "icon", href: "data:image/svg+xml,data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='75' font-size='75'>🚀</text></svg>"
    }
    H.body @
  }

success_page = (auth_cfg) ->
  interval = tonumber(auth_cfg and auth_cfg.heartbeat_interval) or 30
  interval = 30 if interval <= 0
  page {
    H.p "Connexion réussie. Votre accès réseau est actif tant que cette fenêtre est ouverte."
    H.p H.a { href: "/logout" }, "Déconnexion"
    H.script "
      var iv = #{interval} * 1000;
      function ping(){
        fetch('/ping',{method:'GET',credentials:'omit'})
          .then(function(r){ if(r.status===401) location.href='/'; })
          .catch(function(){});
      }
      setInterval(ping, iv);
      ping();
    "
  }

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


refresh_nft = (nft_sess, ip, mac, ttl) ->
  return unless nft_sess
  nft_sess.add_authenticated ip, ttl if ip and ip ~= "unknown"
  nft_sess.add_authenticated_mac mac, ttl if mac and mac ~= "unknown"

handle_login = (req, peer_ip, peer_mac, state) ->
  form = parse_form req.body
  user = form.user
  pass = form.password

  unless user and pass
    return 400, {}, "Missing credentials"

  stored = state.secrets and state.secrets[user]
  unless stored and verify_password pass, stored
    return 401, {}, "Invalid credentials"

  sessions = load_sessions state.sessions_file
  purge_expired sessions

  -- Utiliser directement la MAC fournie par le worker NFQUEUE
  mac = peer_mac

  unless mac and mac ~= "unknown"
    log_warn { action: "auth_login_mac_missing", ip: peer_ip, mac: mac }
    return 401, {}, "Unable to identify client MAC"

  log_info { action: "auth_login_success", user: user, mac: mac, ip: peer_ip }

  ok, err = pcall(->
    add_session sessions, mac, peer_ip, user, state.auth_cfg.session_ttl, state.auth_cfg.idle_timeout
  )
  unless ok
    log_warn { action: "auth_session_add_failed", err: tostring(err) }
    return 500, {}, "Session creation failed"

  ok, err = write_sessions sessions, state.sessions_file
  unless ok
    log_warn { action: "auth_sessions_write_failed", err: err }
    return 500, {}, "Session persistence failed"

  if state.nft_sess
    ok, err = pcall -> refresh_nft state.nft_sess, peer_ip, mac, state.auth_cfg.idle_timeout
    unless ok
      log_warn { action: "auth_nft_refresh_failed", err: tostring(err) }
  else
    log_warn { action: "auth_nft_sess_missing" }

  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, success_page state.auth_cfg

handle_ping = (req, peer_ip, peer_mac, state) ->
  sessions = load_sessions state.sessions_file
  purge_expired sessions

  s = session_for_mac peer_mac, peer_ip, state.sessions_file, sessions

  unless s
    return 401, {}, ""

  mac = s.mac or peer_mac
  now = os.time!
  if (s.expires and now > s.expires) or (s.heartbeat and now > s.heartbeat)
    sessions[mac] = nil
    write_sessions sessions, state.sessions_file
    return 401, {}, ""

  if state.auth_cfg.idle_timeout and state.auth_cfg.idle_timeout > 0
    s.heartbeat = now + state.auth_cfg.idle_timeout
    write_sessions sessions, state.sessions_file

  refresh_nft state.nft_sess, peer_ip, mac, state.auth_cfg.idle_timeout

  204, {}, ""

handle_logout = (req, peer_ip, peer_mac, state) ->
  sessions = load_sessions state.sessions_file
  s = session_for_mac peer_mac, peer_ip, state.sessions_file, sessions


  unless s
    return 404, {}, ""

  mac = s.mac or peer_mac
  if state.nft_sess
    state.nft_sess.del_authenticated peer_ip
    state.nft_sess.del_authenticated_mac s.mac if s.mac

  sessions[mac] = nil
  write_sessions sessions, state.sessions_file

  302, { ["Location"]: "/" }, ""

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
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, register_success_page req

css_content = [[
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.5;
    color: #333;
    background-color: #f5f5f5;
    padding: 1rem;
    max-width: 1200px;
    margin: 0 auto;
  }

  form {
    background: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin: 1rem 0;
  }

  label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 500;
  }

  input[type="text"],
  input[type="password"] {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 1rem;
    margin-bottom: 1rem;
  }

  button {
    background-color: #007bff;
    color: white;
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 0.2s;
  }

  button:hover {
    background-color: #0056b3;
  }

  p {
    margin: 1rem 0;
  }

  a {
    color: #007bff;
    text-decoration: none;
  }

  a:hover {
    text-decoration: underline;
  }

  @media (max-width: 768px) {
    body {
      padding: 0.5rem;
    }

    form {
      padding: 1rem;
    }
  }

  @media (max-width: 480px) {
    body {
      padding: 0.25rem;
    }

    form {
      padding: 0.75rem;
    }
  }
  ]]

handle_request = (req, peer_ip, peer_mac, state) ->
  if req.path == "/" and req.method == "GET"
    return 200, { ["Content-Type"]: "text/html; charset=UTF-8" }, login_page!
  elseif req.path == "/css" and req.method == "GET"
    return 200, { ["Content-Type"]: "text/css" }, css_content
  elseif req.path == "/login" and req.method == "POST"
    return handle_login req, peer_ip, peer_mac, state
  elseif req.path == "/ping" and req.method == "GET"
    return handle_ping req, peer_ip, peer_mac, state
  elseif req.path == "/logout"
    return handle_logout req, peer_ip, peer_mac, state
  elseif req.path == "/register" and req.method == "GET"
    return 200, { ["Content-Type"]: "text/html; charset=UTF-8" }, register_form_page req
  elseif req.path == "/register" and req.method == "POST"
    return handle_register req, peer_ip, peer_mac, state
  else
    return 302, { ["Location"]: "/" }, ""

handle_client = (args) ->
  client = args.client
  state = args.state
  peer_ip = args.peer_ip or "unknown"

  ok, err = pcall ->
    client\settimeout 10

    tls_client, tls_err = ssl.wrap client, state.tls_ctx
    unless tls_client
      log_warn { action: "auth_tls_wrap_failed", err: tls_err }
      client\close!
      return

    ok_hs, hs_err = tls_client\dohandshake!
    unless ok_hs
      log_warn { action: "auth_tls_handshake_failed", err: hs_err }
      tls_client\close!
      return

    peer_mac = get_mac peer_ip
    req, req_err = read_request tls_client
    unless req
      log_warn { action: "auth_request_read_failed", peer: peer_ip, err: req_err }
      tls_client\close!
      return

    status, headers, body = handle_request req, peer_ip, peer_mac, state
    send_response tls_client, status, headers, body
    tls_client\close!

  unless ok
    log_error { action: "auth_client_failed", err: tostring err }
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
  srv\setoption "reuseaddr", true
  ok, err = srv\bind "0.0.0.0", port
  unless ok
    srv\close!
    return nil, err
  srv\listen 8
  srv\settimeout 1
  srv

--- Crée un socket serveur TCP IPv6 (non fatal si non disponible).
-- @tparam number port Port d'écoute
-- @treturn table|nil Socket serveur, ou nil si IPv6 indisponible
make_server6 = (port) ->
  ok6, srv6 = pcall socket.tcp6
  return nil unless ok6 and srv6
  srv6\setoption "reuseaddr", true
  srv6\setoption "ipv6-v6only", true
  ok62, _ = pcall srv6.bind, srv6, "::", port
  unless ok62
    srv6\close!
    return nil
  srv6\listen 8
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
  sessions_file = auth_cfg.sessions_file or AUTH_SESSIONS_FILE
  cert_path = auth_cfg.cert or "tmp/auth.crt"
  key_path = auth_cfg.key or "tmp/auth.key"

  tls_ctx = load_or_generate key_path, cert_path

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
    tls_ctx: tls_ctx
  }

  log_info {
    action: "auth_listening"
    port: port
    ipv4: "0.0.0.0"
    ipv6: listen6 and "::" or nil
    sessions_file: sessions_file
  }

  -- Pipe IPC pour recevoir les infos du worker_auth_queue (MAC/IP)
  -- Créé par main.moon et passé dans state.auth_ipc_rfd
  auth_ipc_rfd = state.auth_ipc_rfd

  while true
    reload_secrets_if_needed state

    while true
      dead_pid = reap_one!
      break unless dead_pid and dead_pid > 0

    readable, _ = socket.select all_servers, nil, 0.1
    if readable
      for srv in *readable
        client = srv\accept!
        if client
          peer_ip = client\getpeername! or "unknown"

          pid = fork_child "AUTH-conn",
            handle_client,
            { client: client, peer_ip: peer_ip, state: state },
            { log_start: false }

          log_info { action: "auth_conn_started", pid: pid, peer: peer_ip }
          client\close!

{ :run }
