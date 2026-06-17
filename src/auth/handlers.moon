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
{ :verify_password, :verify_response, :register_user, :set_record, :parse_record, :valid_username } = require "auth.credentials"
{ :make_nonce, :verify_nonce, :salt_iter_for } = require "auth.challenge"
{ :page, :success_page, :css_content, :password_page, :password_changed_page
  :CRYPTO_JS, :LOGIN_JS, :REGISTER_JS } = require "auth.pages"
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

-- Notification de reload au parent, injectable pour les tests (state.notify_reload).
notify_reload = (state) ->
  fn = (state and state.notify_reload) or signal_parent_reload
  fn!

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
    H.form { id: "register-form", method: "POST", action: "/register" },
      H.label "Utilisateur ", H.input({ name: "user", type: "text" }), H.br!,
      H.label "Mot de passe ", H.input({ name: "password", type: "password", autocomplete: "new-password" }), H.br!,
      H.button { type: "submit" }, "S'inscrire"
    H.a { href: "/" }, "Déjà un compte ? Se connecter"
    H.script CRYPTO_JS .. REGISTER_JS
  }

register_success_page = (req) ->
  page {
    H.p "Compte créé. Vous pouvez maintenant vous connecter.",
    H.a { href: "/" }, "Se connecter"
  }

login_page = ->
  page {
    H.form { id: "login-form", method: "POST", action: "/login" },
      H.label "Utilisateur ", H.input({ name: "user", type: "text", autocomplete: "username" }), H.br!,
      H.label "Mot de passe ", H.input({ name: "password", type: "password", autocomplete: "current-password" }), H.br!,
      H.button { type: "submit" }, "Connexion"
    H.a { href: "/register" }, "Inscription"
    H.script CRYPTO_JS .. LOGIN_JS
  }

-- Émet un challenge (nonce + salt/iter) pour l'utilisateur demandé. Réponse
-- identique qu'il existe ou non (anti-énumération : salt factice déterministe).
-- Le mot de passe n'est jamais transmis ; le client calcule la réponse à partir
-- de ce challenge (cf. auth.pages, auth.challenge).
handle_challenge = (req, peer_ip, peer_mac, state) ->
  form = parse_form req.body
  user = form.user
  -- Repli : si aucun user n'est fourni mais qu'une session est valide (page de
  -- changement de mot de passe), émettre le challenge pour l'utilisateur connecté.
  unless user
    cookie_val = token.get_cookie req.headers.cookie or "", COOKIE_NAME
    p = token.verify cookie_val, state.token_key
    user = p and p.user
  return 400, {}, "Missing user" unless user

  nonce = make_nonce state.token_key, peer_mac, state.auth_cfg and state.auth_cfg.challenge_ttl
  si = salt_iter_for state.secrets, state.token_key, user
  body = "{\"nonce\":\"#{nonce}\",\"salt\":\"#{si.salt}\",\"iter\":#{si.iter}}"
  200, { ["Content-Type"]: "application/json" }, body

-- Repli plaintext autorisé ? Défaut true (compat ascendante) ; recommandé false.
plaintext_allowed = (state) ->
  v = state.auth_cfg and state.auth_cfg.allow_plaintext_login
  if v == nil then true else v and true or false

is_admin_user = (state, user) ->
  admin_users = state.admin_users or {}
  for _, u in ipairs admin_users
    return true if u == user
  state.admin_allow_all_when_empty and #admin_users == 0

handle_login = (req, peer_ip, peer_mac, state) ->
  form = parse_form req.body
  user = form.user
  nonce = form.nonce
  response = form.response
  pass = form.password

  unless user and ((nonce and response) or pass)
    return 400, {}, "Missing credentials"

  stored = state.secrets and state.secrets[user]

  -- Voie challenge-réponse : le client a haché le mot de passe (jamais transmis).
  if nonce and response
    nok, nerr = verify_nonce state.token_key, peer_mac, nonce
    unless nok
      log_warn -> { action: "server_login_nonce_rejected", user: user, ip: peer_ip, err: nerr }
      return 401, {}, "Invalid credentials"
    -- verify_response gère stored=nil (user inconnu) en temps constant.
    unless verify_response stored, nonce, response
      return 401, {}, "Invalid credentials"
  else
    -- Repli plaintext (JS désactivé) : refusé si la politique l'interdit.
    unless plaintext_allowed state
      log_warn -> { action: "server_login_plaintext_refused", user: user, ip: peer_ip }
      return 401, {}, "Invalid credentials"
    unless stored and verify_password pass, stored
      return 401, {}, "Invalid credentials"

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
  is_admin = is_admin_user state, user
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
  salt = form.salt
  iter = tonumber form.iter
  hash = form.hash
  pass = form.password

  -- Voie hachage côté client (préférée) : le mot de passe n'est jamais transmis.
  if user and salt and iter and hash
    unless valid_username user
      return 400, {}, "Adresse de courriel invalide."
    if state.secrets and state.secrets[user]
      return 409, {}, "Ce nom d'utilisateur est déjà pris."
    record = "pbkdf2-sha256:#{iter}:#{salt}:#{hash}"
    unless parse_record record
      return 400, {}, "Invalid record"
    ok, err = set_record user, record, state.secrets_path
    unless ok
      return 500, {}, err or "Registration failed"
    state.secrets = state.secrets or {}
    state.secrets[user] = record
  else
    -- Repli plaintext (JS désactivé) : refusé si la politique l'interdit.
    unless user and pass
      return 400, {}, "Missing credentials"
    unless plaintext_allowed state
      return 401, {}, "Plaintext registration disabled"
    new_secrets, err = register_user user, pass, state.secrets_path, state.secrets
    unless new_secrets
      if err and err\match "déjà"
        return 409, {}, err
      return 500, {}, err or "Registration failed"
    state.secrets = new_secrets

  if not notify_reload state
    log_warn -> { action: "server_reload_signal_failed", parent_pid: tonumber(ffi.C.getppid!) }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, register_success_page req

-- Changement de mot de passe : derrière une session valide. Le client fournit
-- l'enregistrement déjà haché (salt/iter/hash) ; le serveur ne voit jamais le
-- mot de passe en clair (cohérent avec login).
handle_password_change = (req, peer_ip, peer_mac, state) ->
  cookie_val = token.get_cookie req.headers.cookie or "", COOKIE_NAME
  p = token.verify cookie_val, state.token_key
  return 401, {}, "Authentication required" unless p and p.user
  user = p.user

  form = parse_form req.body
  nonce = form.nonce
  response = form.response
  salt = form.salt
  iter = tonumber form.iter
  hash = form.hash
  unless nonce and response and salt and iter and hash
    return 400, {}, "Missing fields"

  -- Exiger l'ancien mot de passe (challenge-réponse) : une session ouverte ne
  -- suffit pas à changer le mot de passe.
  nok = verify_nonce state.token_key, peer_mac, nonce
  unless nok
    return 401, {}, "Invalid credentials"
  stored = state.secrets and state.secrets[user]
  unless verify_response stored, nonce, response
    return 401, {}, "Invalid credentials"

  record = "pbkdf2-sha256:#{iter}:#{salt}:#{hash}"
  unless parse_record record
    return 400, {}, "Invalid record"

  ok, err = set_record user, record, state.secrets_path
  unless ok
    log_warn -> { action: "server_password_change_failed", user: user, err: tostring err }
    return 500, {}, "Password change failed"

  -- Recharge les secrets en mémoire et signale au parent (reload des forks).
  if state.secrets
    state.secrets[user] = record
  notify_reload state
  log_info -> { action: "server_password_changed", user: user }
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, password_changed_page!

handle_request = (req, peer_ip, peer_mac, state) ->
  log_info -> { action: "server_request_received", path: req.path, method: req.method, peer_ip: peer_ip, peer_mac: peer_mac }
  if req.path == "/" and req.method == "GET"
    -- Si une session est déjà valide, afficher la page de succès (évite de
    -- redemander les identifiants après login et après un rafraîchissement).
    cookie_val = token.get_cookie req.headers.cookie or "", COOKIE_NAME
    p = token.verify cookie_val, state.token_key
    if p and p.user and p.mac and p.mac ~= "unknown"
      sessions = load_sessions state.sessions_file
      purge_expired sessions
      if sessions[p.mac\lower!]
        is_admin = is_admin_user state, p.user
        body = success_page state.auth_cfg, os.time!, is_admin
        return 200, { ["Content-Type"]: "text/html; charset=UTF-8" }, body
    return 200, { ["Content-Type"]: "text/html; charset=UTF-8" }, login_page!
  elseif req.path == "/css" and req.method == "GET"
    return 200, { ["Content-Type"]: "text/css" }, css_content
  elseif req.path == "/challenge" and req.method == "POST"
    return handle_challenge req, peer_ip, peer_mac, state
  elseif req.path == "/login" and req.method == "POST"
    log_info -> { action: "server_routing_to_handle_login", path: req.path, method: req.method }
    return handle_login req, peer_ip, peer_mac, state
  elseif req.path == "/password" and req.method == "GET"
    cookie_val = token.get_cookie req.headers.cookie or "", COOKIE_NAME
    p = token.verify cookie_val, state.token_key
    return 302, { ["Location"]: "/" }, "" unless p and p.user
    return 200, { ["Content-Type"]: "text/html; charset=UTF-8" }, password_page!
  elseif req.path == "/password" and req.method == "POST"
    return handle_password_change req, peer_ip, peer_mac, state
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
  :handle_refusals, :handle_challenge, :handle_password_change
  :COOKIE_NAME
}
