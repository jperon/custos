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
      H.meta { name: "viewport", content: "width=device-width, initial-scale=1" }
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
-- Si admin_allow_all_when_empty est true et admin_users est vide, tous les utilisateurs authentifiés sont admin.
-- @tparam table req    Requête HTTP
-- @tparam table state  État du serveur (token_key, admin_users, admin_allow_all_when_empty)
-- @treturn table|nil   Payload du token, ou nil
-- @treturn nil|string  "unauth" si pas de session, "forbidden" si pas admin
check_admin_session = (req, state) ->
  cookie_val = token.get_cookie req.headers.cookie or "", COOKIE_NAME
  return nil, "unauth" unless cookie_val
  p, _ = token.verify cookie_val, state.token_key
  return nil, "unauth" unless p and p.type == "user"
  admin_users = state.admin_users or {}
  -- Si admin_allow_all_when_empty est activé et la liste est vide, tous les utilisateurs sont admin
  if state.admin_allow_all_when_empty and #admin_users == 0
    return p, nil
  for __, u in ipairs admin_users
    return p, nil if u == p.user
  nil, "forbidden"

{ :check_admin_session, :forbidden_page }
