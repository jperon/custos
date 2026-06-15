-- src/auth/handlers.moon
-- Handlers HTTP du portail captif / authentification (login, ping, logout,
-- register) et routage des requêtes. Extrait de auth/server.moon, qui ne garde
-- que la machinerie réseau/TLS/fork et appelle handle_request.

ffi = require "ffi"
ffi.cdef [[
  typedef int pid_t;
  pid_t getppid(void);
  int kill(pid_t pid, int sig);
]]
{ :log_info, :log_warn } = require "log"
token = require "auth.token"
{ :add_session, :purge_expired, :load_sessions, :write_sessions } = require "auth.sessions"
{ :verify_password, :register_user, :update_user_hash } = require "auth.credentials"
{ :page, :success_page, :css_content } = require "auth.pages"
H = require "auth.html"
{ :delete_rule_auth_sets, :refresh_nft } = require "auth.nft_auth_sets"

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

  idle_timeout = state.auth_cfg.idle_timeout or 300
  now = os.time!
  session_expires = now + idle_timeout
  -- Le cookie expire EXACTEMENT avec la session DNS : aucune fenêtre où la page
  -- afficherait « connecté » alors que les sets nft ont déjà expiré. La tolérance
  -- aux pings retardés est absorbée par idle_timeout, pas par une marge séparée.
  token_expires = session_expires
  add_session sessions, mac, peer_ip, user, session_expires
  ok, err = write_sessions sessions, state.sessions_file
  unless ok
    log_warn -> { action: "server_sessions_write_failed", path: state.sessions_file, err: err }
    return 500, {}, "Session persistence failed"
  log_info -> { action: "server_sessions_write_success", path: state.sessions_file, mac: mac }

  -- Refresh nft sets (globaux + per-règle) for authenticated user
  if state.nft_sess
    ok, err = pcall -> refresh_nft state.nft_sess, peer_ip, mac, state.auth_cfg.idle_timeout, user
    unless ok
      log_warn -> { action: "server_nft_refresh_failed", peer: peer_ip, mac: mac, err: tostring(err) }
  else
    log_warn -> { action: "server_nft_sess_missing", peer: peer_ip, mac: mac }

  tok = token.generate "user", user, mac, token_expires, state.token_key
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
  p, tok_err, expired_p = token.verify cookie_val, state.token_key
  unless p
    -- Ping retardé (mis en file par le navigateur) arrivé après le ping
    -- suivant : son token, authentique mais périmé, est hors séquence. Si la
    -- session est encore vivante, c'est qu'un token plus récent l'a déjà
    -- prolongée → 204 no-op (ni refresh, ni nouveau cookie : un token périmé
    -- ne doit jamais pouvoir entretenir une session à lui seul).
    if expired_p and expired_p.mac and expired_p.mac ~= "unknown"
      sessions = load_sessions state.sessions_file
      purge_expired sessions
      if sessions[expired_p.mac\lower!]
        log_info -> { action: "server_ping_stale_token_session_alive", peer_ip: peer_ip, mac: expired_p.mac }
        return 204, {}, ""
    log_info -> { action: "server_ping_token_invalid", peer_ip: peer_ip, err: tok_err }
    return 401, {}, ""

  user = p.user
  mac  = p.mac
  idle_timeout = state.auth_cfg.idle_timeout or 300
  now  = os.time!
  session_expires = now + idle_timeout
  -- Cookie et session DNS expirent ensemble (cf. handle_login).
  token_expires = session_expires

  sessions = load_sessions state.sessions_file
  purge_expired sessions

  -- Rejeter si la session a été explicitement invalidée (logout).
  -- Un token encore cryptographiquement valide ne doit pas recréer une session détruite.
  if mac and mac ~= "unknown" and not sessions[mac\lower!]
    log_info -> { action: "server_ping_session_invalidated", peer_ip: peer_ip, mac: mac }
    return 401, {}, ""

  add_session sessions, mac, peer_ip, user, session_expires
  write_sessions sessions, state.sessions_file

  refresh_nft state.nft_sess, peer_ip, mac, idle_timeout, user

  new_tok = token.generate "user", user, mac, token_expires, state.token_key
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
    delete_rule_auth_sets state.nft_sess, peer_ip, mac, user

  302, { ["Location"]: "/", ["Set-Cookie"]: clear_session_cookie! }, ""

-- Fermeture de fenêtre signalée par le beacon pagehide. Contrairement à
-- /logout, on ne détruit PAS la session : pagehide se déclenche aussi sur un
-- simple reload ou une navigation. On raccourcit seulement l'expiration à une
-- grâce courte : si la page revit, le ping suivant re-prolonge ; sinon la
-- session tombe vite.
handle_bye = (req, peer_ip, peer_mac, state) ->
  cookie_val = token.get_cookie req.headers.cookie or "", COOKIE_NAME
  p = (token.verify cookie_val, state.token_key)
  mac  = (p and p.mac) or peer_mac
  user = p and p.user

  grace = state.auth_cfg.close_grace or 45
  now = os.time!

  if mac and mac ~= "unknown"
    sessions = load_sessions state.sessions_file
    s = sessions[mac\lower!]
    if s
      capped = now + grace
      if not s.expires or s.expires > capped
        s.expires = capped
        write_sessions sessions, state.sessions_file
        refresh_nft state.nft_sess, peer_ip, mac, grace, user or s.user if state.nft_sess
        log_info -> { action: "server_bye_grace", mac: mac, grace: grace }

  204, {}, ""

json_escape = (s) ->
  return "" unless s
  s = tostring s
  s = s\gsub "\\", "\\\\"
  s = s\gsub "\"", "\\\""
  s = s\gsub "\n", "\\n"
  s = s\gsub "\r", "\\r"
  s = s\gsub "\t", "\\t"
  s

-- Liste des derniers domaines refusés pour la MAC du client connecté.
-- Lecture seule : ni session, ni nft, ni cookie. Source = recent-blocks.tsv,
-- écrit en continu par worker_events (format : mac\tqname\treason\tcount\tlast_ts).
REFUSALS_MAX = 50

handle_refusals = (req, peer_ip, peer_mac, state) ->
  cookie_val = token.get_cookie req.headers.cookie or "", COOKIE_NAME
  p = token.verify cookie_val, state.token_key
  return 401, {}, "" unless p

  mac = p.mac
  return 200, { ["Content-Type"]: "application/json" }, "[]" unless mac and mac ~= "unknown"
  mac_lc = mac\lower!

  events_dir = state.events_dir or "/tmp/custos/events"
  fh = io.open "#{events_dir}/recent-blocks.tsv", "r"
  return 200, { ["Content-Type"]: "application/json" }, "[]" unless fh

  parts = {}
  for line in fh\lines!
    break if #parts >= REFUSALS_MAX
    l_mac, qname, reason, count, ts = line\match "^([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)$"
    continue unless l_mac and l_mac\lower! == mac_lc
    parts[#parts + 1] = "{\"qname\":\"#{json_escape qname}\",\"reason\":\"#{json_escape reason}\",\"count\":#{tonumber(count) or 0},\"ts\":#{tonumber(ts) or 0}}"
  fh\close!

  200, { ["Content-Type"]: "application/json" }, "[#{table.concat parts, ","}]"

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
  elseif req.path == "/refusals" and req.method == "GET"
    return handle_refusals req, peer_ip, peer_mac, state
  elseif req.path == "/logout"
    return handle_logout req, peer_ip, peer_mac, state
  elseif req.path == "/bye"
    return handle_bye req, peer_ip, peer_mac, state
  elseif req.path == "/register" and req.method == "GET"
    return 200, { ["Content-Type"]: "text/html; charset=UTF-8" }, register_form_page req
  elseif req.path == "/register" and req.method == "POST"
    return handle_register req, peer_ip, peer_mac, state
  elseif req.path\match "^/admin"
    webui_router = require "webui.router"
    return webui_router.dispatch req, state
  else
    return 302, { ["Location"]: "/" }, ""

{
  :make_session_cookie, :clear_session_cookie, :signal_parent_reload
  :url_decode, :parse_form, :register_form_page, :register_success_page, :login_page
  :handle_login, :handle_ping, :handle_logout, :handle_bye, :handle_register, :handle_request
  :handle_refusals
  :COOKIE_NAME
}
