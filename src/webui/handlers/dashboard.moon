-- src/webui/handlers/dashboard.moon
-- GET /admin/ — Vue d'ensemble.

H      = require "auth.html"
{ :css } = require "webui.css"
config = require "config"

nav_html = ->
  H.nav {
    H.a { href: "/admin/" }, "Dashboard"
    H.a { href: "/admin/config/filter/rules" }, "Règles"
    H.a { href: "/admin/config/" }, "Configuration"
    H.a { href: "/admin/system/status" }, "Statut"
    H.a { href: "/admin/logout" }, "Déconnexion"
  }

page = (title, body_content) ->
  "<!DOCTYPE html>\n" .. H.html {
    H.head {
      H.meta { charset: "UTF-8" }
      H.title "Admin — #{title}"
      H.style css!
    }
    H.body {
      nav_html!
      H.h1 title
      body_content
    }
  }

handle_dashboard = (req, state) ->
  rules = (config.filter or {}).rules or {}
  n_rules = #rules

  s1 = H.section {
    H.h2 "Filtre DNS"
    H.p "Nombre de règles : #{n_rules}"
    H.p { H.a { href: "/admin/config/filter/rules" }, "Éditer les règles" }
  }
  s2 = H.section {
    H.h2 "Configuration"
    H.p { H.a { href: "/admin/config/" }, "Toutes les sections" }
    H.p { H.a { href: "/admin/system/status" }, "Statut des workers" }
  }
  s3 = H.section {
    H.h2 "Rechargement"
    H.p "Après modification de la configuration, rechargez les workers DNS."
    H.form { method: "POST", action: "/admin/system/reload" },
      H.button { type: "submit" }, "Recharger maintenant"
  }

  200, { ["Content-Type"]: "text/html; charset=UTF-8" }, page "Dashboard", s1 .. s2 .. s3

{ :handle_dashboard, :nav_html, :page }
