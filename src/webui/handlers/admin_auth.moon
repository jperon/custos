-- src/webui/handlers/admin_auth.moon
-- Vérifie qu'une session utilisateur valide appartient à la liste admin_users.
-- Aucune page de login dédiée : utiliser le portail captif (/login).

token  = require "auth.token"
H      = require "auth.html"
{ :css } = require "webui.css"

COOKIE_NAME = "custos_session"

-- Page 403 minimale
forbidden_page = (user) ->
  "<!DOCTYPE html>\n" .. H.html {
    H.head {
      H.meta { charset: "UTF-8" }
      H.title "Accès refusé"
      H.style css!
    }
    H.body {
      H.h1 "Accès refusé"
      H.p "L'utilisateur " .. H.strong(user) .. " n'a pas les droits administrateur."
      H.p { H.a { href: "/logout" }, "Se déconnecter" }
    }
  }

--- Extrait et vérifie le token de session depuis les headers de la requête,
-- puis contrôle que l'utilisateur est dans state.admin_users.
-- @tparam table req    Requête HTTP
-- @tparam table state  État du serveur (token_key, admin_users)
-- @treturn table|nil   Payload du token, ou nil
-- @treturn nil|string  "unauth" si pas de session, "forbidden" si pas admin
check_admin_session = (req, state) ->
  cookie_val = token.get_cookie req.headers.cookie or "", COOKIE_NAME
  return nil, "unauth" unless cookie_val
  p, err = token.verify cookie_val, state.token_key
  return nil, "unauth" unless p and p.type == "user"
  admin_users = state.admin_users or {}
  for _, u in ipairs admin_users
    return p, nil if u == p.user
  nil, "forbidden"

{ :check_admin_session, :forbidden_page }
