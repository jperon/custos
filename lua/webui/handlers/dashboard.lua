local H = require("auth.html")
local css
css = require("webui.css").css
local config = require("config")
local nav_html
nav_html = function()
  return H.nav({
    H.a({
      href = "/admin/"
    }, "Dashboard"),
    H.a({
      href = "/admin/config/filter/rules"
    }, "Règles"),
    H.a({
      href = "/admin/config/filter/lists"
    }, "Listes"),
    H.a({
      href = "/admin/config/"
    }, "Configuration"),
    H.a({
      href = "/admin/system/status"
    }, "Statut"),
    H.a({
      href = "/admin/logout"
    }, "Déconnexion"),
    H.form({
      method = "POST",
      action = "/admin/system/reload",
      class = "nav-reload"
    }, H.button({
      type = "submit"
    }, "Recharger maintenant"))
  })
end
local page
page = function(title, body_content)
  return "<!DOCTYPE html>\n" .. H.html({
    H.head({
      H.meta({
        charset = "UTF-8"
      }),
      H.meta({
        name = "viewport",
        content = "width=device-width, initial-scale=1"
      }),
      H.title("Admin — " .. tostring(title)),
      H.style(css())
    }),
    H.body({
      nav_html(),
      H.h1(title),
      body_content
    })
  })
end
local handle_dashboard
handle_dashboard = function(req, state)
  local rules = (config.filter or { }).rules or { }
  local n_rules = #rules
  local s1 = H.section({
    H.h2("Filtre DNS"),
    H.p("Nombre de règles : " .. tostring(n_rules)),
    H.p({
      H.a({
        href = "/admin/config/filter/rules"
      }, "Éditer les règles")
    })
  })
  local s2 = H.section({
    H.h2("Configuration"),
    H.p({
      H.a({
        href = "/admin/config/"
      }, "Toutes les sections")
    }),
    H.p({
      H.a({
        href = "/admin/system/status"
      }, "État du service DNS")
    })
  })
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, page("Dashboard", s1 .. s2)
end
return {
  handle_dashboard = handle_dashboard,
  nav_html = nav_html,
  page = page
}
