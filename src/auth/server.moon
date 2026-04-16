-- src/auth/server.moon
-- Serveur HTTP minimal pour l'authentification des utilisateurs.
--
-- Endpoints :
--   GET  /        → page de connexion HTML
--   POST /login   → vérification des credentials, création de session
--   GET  /logout  → suppression de la session de l'IP source
--
-- Dépendances : luasocket.
-- Les credentials sont fournis par auth/credentials, les sessions par auth/sessions.

socket = require "socket"
ssl    = require "ssl"
cert   = require "auth.cert"

{ :verify_password, :load_secrets, :register_user } = require "auth.credentials"
{ :add_session, :purge_expired, :write_sessions } = require "auth.sessions"
{ :log_info, :log_warn }            = require "log"
neigh                               = require "neigh"

-- ── Page HTML ────────────────────────────────────────────────────

LOGIN_PAGE = [[
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CustosVirginum — Authentification</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: system-ui, sans-serif;
      background: #f4f4f4;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      margin: 0;
    }
    .card {
      background: white;
      padding: 2rem;
      border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,.15);
      width: 100%;
      max-width: 380px;
    }
    h1 { font-size: 1.3rem; margin: 0 0 1.5rem; color: #222; }
    label { display: block; margin-bottom: 1rem; }
    label span { display: block; font-size: .85rem; color: #555; margin-bottom: .3rem; }
    input[type=text], input[type=password] {
      width: 100%;
      padding: .5rem .7rem;
      border: 1px solid #ccc;
      border-radius: 4px;
      font-size: 1rem;
    }
    button {
      width: 100%;
      padding: .6rem;
      background: #2563eb;
      color: white;
      border: none;
      border-radius: 4px;
      font-size: 1rem;
      cursor: pointer;
      margin-top: .5rem;
    }
    button:hover { background: #1d4ed8; }
    .msg { margin-top: 1rem; padding: .6rem; border-radius: 4px; font-size: .9rem; }
    .msg.ok  { background: #dcfce7; color: #166534; }
    .msg.err { background: #fee2e2; color: #991b1b; }
    .link { text-align: center; margin-top: 1rem; font-size: .9rem; }
    .link a { color: #2563eb; text-decoration: none; }
    .link a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <h1>CustosVirginum</h1>
    <div %AUTH_HIDDEN%>
      <form method="post" action="/login">
        <label>
          <span>Nom d'utilisateur</span>
          <input type="text" name="user" required autofocus>
        </label>
        <label>
          <span>Mot de passe</span>
          <input type="password" name="password" required>
        </label>
        <button type="submit">Se connecter</button>
      </form>
      <div class="link"><a href="/register">Créer un compte</a></div>
    </div>
    %MSG%
  </div>
</body>
</html>
]]

REGISTER_PAGE = [[
<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CustosVirginum — Inscription</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: system-ui, sans-serif;
      background: #f4f4f4;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      margin: 0;
    }
    .card {
      background: white;
      padding: 2rem;
      border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,.15);
      width: 100%;
      max-width: 380px;
    }
    h1 { font-size: 1.3rem; margin: 0 0 1.5rem; color: #222; }
    label { display: block; margin-bottom: 1rem; }
    label span { display: block; font-size: .85rem; color: #555; margin-bottom: .3rem; }
    input[type=text], input[type=password] {
      width: 100%;
      padding: .5rem .7rem;
      border: 1px solid #ccc;
      border-radius: 4px;
      font-size: 1rem;
    }
    button {
      width: 100%;
      padding: .6rem;
      background: #16a34a;
      color: white;
      border: none;
      border-radius: 4px;
      font-size: 1rem;
      cursor: pointer;
      margin-top: .5rem;
    }
    button:hover { background: #15803d; }
    .msg { margin-top: 1rem; padding: .6rem; border-radius: 4px; font-size: .9rem; }
    .msg.ok  { background: #dcfce7; color: #166534; }
    .msg.err { background: #fee2e2; color: #991b1b; }
    .link { text-align: center; margin-top: 1rem; font-size: .9rem; }
    .link a { color: #2563eb; text-decoration: none; }
    .link a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Créer un compte</h1>
    <form method="post" action="/register">
      <label>
        <span>Nom d'utilisateur</span>
        <input type="text" name="user" required autofocus minlength="3" maxlength="32" pattern="[a-zA-Z0-9_.\-]+">
      </label>
      <label>
        <span>Mot de passe (8 caractères minimum)</span>
        <input type="password" name="password" required minlength="8">
      </label>
      <label>
        <span>Confirmer le mot de passe</span>
        <input type="password" name="password2" required minlength="8">
      </label>
      <button type="submit">Créer le compte</button>
    </form>
    <div class="link"><a href="/">Déjà un compte ? Se connecter</a></div>
    %MSG%
  </div>
</body>
</html>
]]

success_page_tmp, _ = LOGIN_PAGE\gsub "%%MSG%%", '<p class="msg ok">Connexion réussie. Votre accès réseau est actif.</p>'
SUCCESS_PAGE_RAW, _ = success_page_tmp\gsub "%%AUTH_HIDDEN%%", 'style="display:none"'
SUCCESS_PAGE = SUCCESS_PAGE_RAW

--- Construit la page de succès avec le heartbeat JS intégré.
-- @tparam number interval Intervalle de ping en secondes
-- @treturn string Page HTML
make_success_page = (interval) ->
  js = string.format([[
<script>
(function(){
  var iv = %d * 1000;
  function ping(){
    fetch('/ping',{method:'GET',credentials:'omit'})
      .then(function(r){ if(r.status===401) location.href='/'; })
      .catch(function(){});
  }
  setInterval(ping, iv);
  ping();
})();
</script>]], interval)
  res, _ = LOGIN_PAGE\gsub "%%MSG%%", '<p class="msg ok">Connexion r\xc3\xa9ussie. Votre acc\xc3\xa8s r\xc3\xa9seau est actif tant que cette page reste ouverte.</p>' .. js
  res2, _ = res\gsub "%%AUTH_HIDDEN%%", 'style="display:none"'
  res2

failure_page = (reason) ->
  res, _ = LOGIN_PAGE\gsub "%%MSG%%", "<p class=\"msg err\">#{reason}</p>"
  res2, _ = res\gsub "%%AUTH_HIDDEN%%", ""
  res2

register_failure_page = (reason) ->
  res, _ = REGISTER_PAGE\gsub "%%MSG%%", "<p class=\"msg err\">#{reason}</p>"
  res

-- Version sans message (accueil)
home_page_raw, _  = LOGIN_PAGE\gsub "%%MSG%%", ""
home_page_raw2, _ = home_page_raw\gsub "%%AUTH_HIDDEN%%", ""
home_page = home_page_raw2

home_register_page_raw, _ = REGISTER_PAGE\gsub "%%MSG%%", ""
home_register_page = home_register_page_raw

-- ── Parsing HTTP minimal ──────────────────────────────────────────

--- Lit les headers HTTP depuis un socket TLS.
-- Retourne la méthode, le path, et les headers sous forme de table.
-- @tparam table  sock   Socket TLS (luasec wrappé)
-- @treturn string, string, table  méthode, path, headers
-- @treturn nil, string           en cas d'erreur
read_request = (sock) ->
  -- Ligne de requête
  line, err = sock\receive "*l"
  return nil, err unless line
  method, path = line\match "^(%u+)%s+([^%s]+)"
  return nil, "bad request line: #{line}" unless method

  -- Headers
  headers = {}
  content_length = 0
  while true
    hline, herr = sock\receive "*l"
    break if not hline or hline == ""
    return nil, herr if not hline
    name, val = hline\match "^([^:]+):%s*(.*)"
    if name
      headers[name\lower!] = val
      if name\lower! == "content-length"
        content_length = tonumber(val) or 0

  -- Corps (pour POST)
  body = ""
  if content_length > 0
    body = sock\receive content_length

  method, path, headers, body

--- Décode une chaîne encodée en application/x-www-form-urlencoded.
-- @tparam string s Chaîne encodée
-- @treturn table  Table clé→valeur
decode_form = (s) ->
  t = {}
  for pair in (s or "")\gmatch "[^&]+"
    k, v = pair\match "^([^=]+)=?(.*)$"
    if k
      decode = (x) -> x\gsub("+", " ")\gsub("%%(%x%x)", (h) -> string.char tonumber h, 16)
      t[decode k] = decode v
  t

-- ── Réponses HTTP ─────────────────────────────────────────────────

http_response = (sock, status, body, extra_headers) ->
  extra_headers = extra_headers or ""
  resp = table.concat {
    "HTTP/1.1 #{status}\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n"
    "Content-Length: #{#body}\r\n"
    "Connection: close\r\n"
    "X-Frame-Options: DENY\r\n"
    "X-Content-Type-Options: nosniff\r\n"
    extra_headers
    "\r\n"
    body
  }
  sock\send resp

http_redirect = (sock, location) ->
  resp = "HTTP/1.1 303 See Other\r\nLocation: #{location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  sock\send resp

-- ── Rate-limiting pour l'inscription ────────────────────────────────

--- Vérifie si une IP a dépassé la limite de tentatives d'inscription.
-- @tparam table  register_attempts Table {ip → {count, ts}}
-- @tparam string peer_ip          Adresse IP du client
-- @tparam number max_attempts     Nombre max de tentatives dans la fenêtre
-- @tparam number window_sec       Durée de la fenêtre en secondes
-- @treturn boolean true si l'IP est au-dessus de la limite
register_rate_exceeded = (register_attempts, peer_ip, max_attempts, window_sec) ->
  now = os.time!
  entry = register_attempts[peer_ip]
  if entry
    if now - entry.ts > window_sec
      register_attempts[peer_ip] = { count: 1, ts: now }
      return false
    entry.count += 1
    if entry.count > max_attempts
      return true
  else
    register_attempts[peer_ip] = { count: 1, ts: now }
  false

-- ── Gestionnaire de connexion ─────────────────────────────────────

--- Gère une connexion HTTP entrante.
-- @tparam table  raw_sock    Socket TCP brut (luasocket)
-- @tparam table  secrets     Table {user → hash}
-- @tparam table  sessions    Table de sessions (modifiée en place)
-- @tparam table  auth_cfg    Configuration auth (session_ttl, idle_timeout, sessions_file)
-- @tparam string peer_ip     Adresse IP du client
-- @tparam string success_pg  Page HTML de succès (avec JS heartbeat intégré)
-- @tparam table|nil nft_sess Module auth.nft_sessions (ou nil si portail captif désactivé)
-- @tparam string secrets_path Chemin du fichier secrets
-- @tparam table register_attempts Table de rate-limiting pour l'inscription
-- @tparam string peer_mac    Adresse MAC du client
handle_connection = (raw_sock, secrets, sessions, auth_cfg, peer_ip, success_pg, nft_sess, secrets_path, register_attempts, peer_mac) ->
  raw_sock\settimeout 10

  method, path, headers, body = read_request raw_sock
  unless method
    raw_sock\close!
    return

  if method == "GET" and (path == "/" or path == "/login")
    -- Vérifie si l'IP a déjà une session valide
    s = sessions[peer_ip]
    now = os.time!
    if s and now <= s.expires and (not s.heartbeat or now <= s.heartbeat)
      http_response raw_sock, "200 OK", success_pg
      log_info { action: "auth_already_logged", ip: peer_ip, mac: peer_mac, user: s.user }
    else
      http_response raw_sock, "200 OK", home_page

  elseif method == "GET" and path == "/ping"
    s = sessions[peer_ip]
    now = os.time!
    if s and now <= s.expires and (not s.heartbeat or now <= s.heartbeat)
      if auth_cfg.idle_timeout and auth_cfg.idle_timeout > 0
        s.heartbeat = now + auth_cfg.idle_timeout
        ok2, err3 = write_sessions sessions, auth_cfg.sessions_file
        log_warn { action: "auth_write_failed", err: err3 } unless ok2
        if nft_sess
          ok_nft = nft_sess.add_authenticated peer_ip, auth_cfg.idle_timeout
          log_warn { action: "auth_nft_add_failed", ip: peer_ip, ttl: auth_cfg.idle_timeout } unless ok_nft
          if s.mac
            ok_mac = nft_sess.add_authenticated_mac s.mac, auth_cfg.idle_timeout
            log_warn { action: "auth_nft_mac_add_failed", mac: s.mac, ttl: auth_cfg.idle_timeout } unless ok_mac
      http_response raw_sock, "204 No Content", ""
    else
      http_response raw_sock, "401 Unauthorized", ""

  elseif method == "GET" and path == "/logout"
    s = sessions[peer_ip]
    sessions[peer_ip] = nil
    if nft_sess
      nft_sess.del_authenticated peer_ip
      if s and s.mac
        nft_sess.del_authenticated_mac s.mac
    ok2, err3 = write_sessions sessions, auth_cfg.sessions_file
    log_warn { action: "auth_write_failed", err: err3 } unless ok2
    http_redirect raw_sock, "/"
    log_info { action: "auth_logout", ip: peer_ip, mac: peer_mac }

  elseif method == "GET" and path == "/register"
    http_response raw_sock, "200 OK", home_register_page

  elseif method == "POST" and path == "/login"
    form = decode_form body
    user = form.user or ""
    pass = form.password or ""
    stored = secrets[user]

    if stored and pass ~= "" and verify_password pass, stored
      purge_expired sessions
      mac = peer_mac ~= "unknown" and peer_mac or nil
      add_session sessions, peer_ip, user, auth_cfg.session_ttl, auth_cfg.idle_timeout, mac
      if nft_sess
        ok_nft = nft_sess.add_authenticated peer_ip, auth_cfg.session_ttl
        log_warn { action: "auth_nft_add_failed", ip: peer_ip, ttl: auth_cfg.session_ttl } unless ok_nft
        if mac
          ok_mac = nft_sess.add_authenticated_mac mac, auth_cfg.session_ttl
          log_warn { action: "auth_nft_mac_add_failed", mac: mac, ttl: auth_cfg.session_ttl } unless ok_mac
      ok2, err3 = write_sessions sessions, auth_cfg.sessions_file
      log_warn { action: "auth_write_failed", err: err3 } unless ok2
      http_response raw_sock, "200 OK", success_pg
      log_info { action: "auth_login_ok", ip: peer_ip, mac: peer_mac, user: user }
    else
      http_response raw_sock, "401 Unauthorized",
        failure_page "Nom d'utilisateur ou mot de passe incorrect."
      log_warn { action: "auth_login_failed", ip: peer_ip, mac: peer_mac, user: user }

  elseif method == "POST" and path == "/register"
    max_attempts = auth_cfg.register_rate_limit or 3
    window_sec = auth_cfg.register_rate_window or 300
    if register_rate_exceeded register_attempts, peer_ip, max_attempts, window_sec
      http_response raw_sock, "429 Too Many Requests",
        register_failure_page "Trop de tentatives d'inscription. Réessayez plus tard."
      log_warn { action: "auth_register_rate_limited", ip: peer_ip, mac: peer_mac }
    else
      form = decode_form body
      user = form.user or ""
      pass = form.password or ""
      pass2 = form.password2 or ""
      if pass ~= pass2
        http_response raw_sock, "400 Bad Request",
          register_failure_page "Les mots de passe ne correspondent pas."
        log_warn { action: "auth_register_password_mismatch", ip: peer_ip, mac: peer_mac, user: user }
      else
        new_secrets, reg_err = register_user user, pass, secrets_path, secrets
        if new_secrets
          purge_expired sessions
          mac = peer_mac ~= "unknown" and peer_mac or nil
          add_session sessions, peer_ip, user, auth_cfg.session_ttl, auth_cfg.idle_timeout, mac
          if nft_sess
            ok_nft = nft_sess.add_authenticated peer_ip, auth_cfg.session_ttl
            log_warn { action: "auth_nft_add_failed", ip: peer_ip, ttl: auth_cfg.session_ttl } unless ok_nft
            if mac
              ok_mac = nft_sess.add_authenticated_mac mac, auth_cfg.session_ttl
              log_warn { action: "auth_nft_mac_add_failed", mac: mac, ttl: auth_cfg.session_ttl } unless ok_mac
          ok2, err3 = write_sessions sessions, auth_cfg.sessions_file
          log_warn { action: "auth_write_failed", err: err3 } unless ok2
          -- Met à jour la table des secrets en place pour la rendre visible au parent
          secrets[user] = new_secrets[user]
          http_response raw_sock, "200 OK", success_pg
          log_info { action: "auth_register_ok", ip: peer_ip, mac: peer_mac, user: user }
        else
          user_msg = reg_err
          status = "400 Bad Request"
          if reg_err\match "déjà pris"
            user_msg = "Impossible de créer ce compte. Veuillez choisir un autre nom."
            status = "409 Conflict"
          http_response raw_sock, status,
            register_failure_page user_msg
          log_warn { action: "auth_register_failed", ip: peer_ip, mac: peer_mac, user: user, err: reg_err }

  else
    http_response raw_sock, "404 Not Found", "<h1>404</h1>"

  raw_sock\close!

-- ── Création des sockets serveur ─────────────────────────────────

--- Crée un socket serveur TCP IPv4.
-- @tparam string host Adresse d'écoute (ex. "0.0.0.0")
-- @tparam number port Port d'écoute
-- @treturn table|nil Socket serveur, ou nil + erreur
make_server4 = (host, port) ->
  srv = socket.tcp!
  srv\setoption "reuseaddr", true
  ok4, err = srv\bind host, port
  unless ok4
    srv\close!
    return nil, err
  srv\listen 8
  srv\settimeout 1
  srv

--- Crée un socket serveur TCP IPv6.
-- @tparam number port Port d'écoute
-- @treturn table|nil Socket serveur, ou nil (IPv6 non disponible — pas fatal)
make_server6 = (port) ->
  ok6, srv6 = pcall socket.tcp6
  return nil unless ok6 and srv6
  srv6\setoption "reuseaddr", true
  srv6\setoption "ipv6-v6only", true
  ok62, _err = srv6\bind "::", port
  unless ok62
    srv6\close!
    return nil
  srv6\listen 8
  srv6\settimeout 1
  srv6

-- ── Boucle principale ────────────────────────────────────────────

--- Démarre la boucle d'acceptation HTTPS.
-- @tparam table secrets       Table {user → hash}
-- @tparam table auth_cfg      Configuration auth
-- @tparam function|nil reload_fn  Fonction appelée pour recharger les secrets (SIGHUP)
-- @tparam table|nil nft_sess  Module auth.nft_sessions
-- @tparam string|nil secrets_path  Chemin vers le fichier secrets
run = (secrets, auth_cfg, reload_fn, nft_sess, secrets_path) ->
  port = auth_cfg.port or 33443
  host = auth_cfg.host or "::"
  secrets_path = auth_cfg.secrets or "cfg/secrets"

  -- Page de succès avec JS heartbeat intégré (construit une seule fois)
  hb_interval = auth_cfg.heartbeat_interval or 30
  success_pg  = make_success_page hb_interval

  -- Contexte TLS (créé une seule fois pour le serveur HTTPS)
  key_path  = auth_cfg.key  or "tmp/auth.key"
  cert_path = auth_cfg.cert or "tmp/auth.crt"
  ssl_ctx = cert.load_or_generate key_path, cert_path

  -- Sockets d'écoute HTTPS : on tente toujours IPv4 + IPv6
  listen4, err4 = make_server4 "0.0.0.0", port
  error "Impossible de démarrer le serveur IPv4 sur port #{port} : #{err4}" unless listen4
  listen6 = make_server6 port
  if listen6
    log_info { action: "auth_listening", ipv4: "0.0.0.0", ipv6: "::", port: port }
  else
    log_info { action: "auth_listening", ipv4: "0.0.0.0", port: port }

  sessions = {}

  register_attempts = {}

  all_servers = { listen4 }
  if listen6
    all_servers[#all_servers + 1] = listen6

  while true
    -- Rechargement des secrets sur SIGHUP
    if reload_fn
      new_secrets = reload_fn!
      secrets = new_secrets if new_secrets

    readable = socket.select all_servers, nil, 1
    for srv in *(readable or {})
      raw_client, _err = srv\accept!
      if raw_client
        peer_ip  = raw_client\getpeername!
        peer_ip  = tostring peer_ip
        peer_mac = neigh.get_mac peer_ip
        -- Connexion HTTPS : enveloppe TLS puis logique d'authentification
        conn = ssl.wrap raw_client, ssl_ctx
        if conn
          ok_hs, _hs_err = conn\dohandshake!
          if ok_hs
            handle_connection conn, secrets, sessions, auth_cfg, peer_ip, success_pg, nft_sess, secrets_path, register_attempts, peer_mac
          else
            conn\close!
        else
          raw_client\close!

{ :run, :handle_connection, :decode_form, :failure_page, :home_page, :SUCCESS_PAGE }
