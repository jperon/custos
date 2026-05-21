-- src/webui/handlers/admin_auth.moon
-- Authentification de l'administrateur webui.
-- Login/logout via PBKDF2 + token HMAC (même mécanique que le portail captif).
-- Route /admin/login (GET + POST), /admin/logout (GET).

H      = require "auth.html"
token  = require "auth.token"
{ :verify_password } = require "auth.credentials"
{ :css } = require "webui.css"

COOKIE_ADMIN = "custos_admin"

-- ── Helpers ────────────────────────────────────────────────────────────────

make_admin_cookie = (tok) ->
  "#{COOKIE_ADMIN}=#{tok}; Path=/admin; HttpOnly; SameSite=Strict"

clear_admin_cookie = ->
  "#{COOKIE_ADMIN}=; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=0"

--- Extrait et vérifie le token admin depuis les headers de la requête.
-- @tparam table req     Requête HTTP (req.headers.cookie)
-- @tparam string key    Clé HMAC
-- @treturn table|nil    Payload du token ou nil si invalide/absent
check_admin_session = (req, key) ->
  cookie_val = token.get_cookie req.headers.cookie or "", COOKIE_ADMIN
  return nil unless cookie_val
  p, err = token.verify cookie_val, key
  return nil unless p and p.type == "admin"
  p

-- ── Pages ─────────────────────────────────────────────────────────────────

login_page = (error_msg) ->
  "<!DOCTYPE html>\n" .. H.html {
    H.head {
      H.meta { charset: "UTF-8" }
      H.title "CustosVirginum — Administration"
      H.style css!
    }
    H.body {
      H.h1 "CustosVirginum — Administration"
      (if error_msg then H.div { class: "flash error" }, error_msg else "")
      H.form { method: "POST", action: "/admin/login" },
        H.label "Utilisateur"
        H.input { name: "user", type: "text", required: true }
        H.label "Mot de passe"
        H.input { name: "password", type: "password", required: true }
        H.button { type: "submit" }, "Connexion"
    }
  }

-- ── Handlers ─────────────────────────────────────────────────────────────

--- GET /admin/login
handle_login_get = (req, state) ->
  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, login_page nil

--- POST /admin/login
handle_login_post = (req, state) ->
  parse_form = (body) ->
    return {} unless body
    out = {}
    for k, v in (body or "")\gmatch "([^&=]+)=([^&]*)"
      dec = (s) -> (s\gsub "%%(%x%x)", (h) -> string.char tonumber h, 16)\gsub "+", " "
      out[dec k] = dec v
    out

  form = parse_form req.body
  user = form.user
  pass = form.password

  unless user and pass
    return 400, { ["Content-Type"]: "text/html; charset=UTF-8" }, login_page "Identifiants manquants"

  stored = state.secrets and state.secrets[user]
  unless stored
    return 401, { ["Content-Type"]: "text/html; charset=UTF-8" }, login_page "Identifiants invalides"

  ok, _ = verify_password pass, stored
  unless ok
    return 401, { ["Content-Type"]: "text/html; charset=UTF-8" }, login_page "Identifiants invalides"

  idle_timeout = state.auth_cfg and state.auth_cfg.session_ttl or 3600
  idle_timeout = 3600 if idle_timeout == 0
  now = os.time!
  tok = token.generate "admin", user, "", now + idle_timeout, state.token_key

  302, {
    ["Location"]: "/admin/"
    ["Set-Cookie"]: make_admin_cookie tok
  }, ""

--- GET /admin/logout
handle_logout = (req, state) ->
  302, {
    ["Location"]: "/admin/login"
    ["Set-Cookie"]: clear_admin_cookie!
  }, ""

{ :check_admin_session, :handle_login_get, :handle_login_post, :handle_logout }
