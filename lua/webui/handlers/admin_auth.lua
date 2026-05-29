local token = require("auth.token")
local H = require("auth.html")
local css
css = require("webui.css").css
local COOKIE_NAME = "custos_session"
local forbidden_page
forbidden_page = function(user)
  return "<!DOCTYPE html>\n" .. H.html({
    H.head({
      H.meta({
        charset = "UTF-8"
      }),
      H.meta({
        name = "viewport",
        content = "width=device-width, initial-scale=1"
      }),
      H.title("Accès refusé"),
      H.style(css())
    }),
    H.body({
      H.h1("Accès refusé"),
      H.p("L'utilisateur " .. H.strong(user) .. " n'a pas les droits administrateur."),
      H.p({
        H.a({
          href = "/logout"
        }, "Se déconnecter")
      })
    })
  })
end
local check_admin_session
check_admin_session = function(req, state)
  local cookie_val = token.get_cookie(req.headers.cookie or "", COOKIE_NAME)
  if not (cookie_val) then
    return nil, "unauth"
  end
  local p, _ = token.verify(cookie_val, state.token_key)
  if not (p and p.type == "user") then
    return nil, "unauth"
  end
  local admin_users = state.admin_users or { }
  if state.admin_allow_all_when_empty and #admin_users == 0 then
    return p, nil
  end
  for __, u in ipairs(admin_users) do
    if u == p.user then
      return p, nil
    end
  end
  return nil, "forbidden"
end
return {
  check_admin_session = check_admin_session,
  forbidden_page = forbidden_page
}
