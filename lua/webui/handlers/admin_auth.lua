local H = require("auth.html")
local token = require("auth.token")
local verify_password
verify_password = require("auth.credentials").verify_password
local css
css = require("webui.css").css
local COOKIE_ADMIN = "custos_admin"
local make_admin_cookie
make_admin_cookie = function(tok)
  return tostring(COOKIE_ADMIN) .. "=" .. tostring(tok) .. "; Path=/admin; HttpOnly; SameSite=Strict"
end
local clear_admin_cookie
clear_admin_cookie = function()
  return tostring(COOKIE_ADMIN) .. "=; Path=/admin; HttpOnly; SameSite=Strict; Max-Age=0"
end
local check_admin_session
check_admin_session = function(req, key)
  local cookie_val = token.get_cookie(req.headers.cookie or "", COOKIE_ADMIN)
  if not (cookie_val) then
    return nil
  end
  local p, err = token.verify(cookie_val, key)
  if not (p and p.type == "admin") then
    return nil
  end
  return p
end
local login_page
login_page = function(error_msg)
  return "<!DOCTYPE html>\n" .. H.html({
    H.head({
      H.meta({
        charset = "UTF-8"
      }),
      H.title("CustosVirginum — Administration"),
      H.style(css())
    }),
    H.body({
      H.h1("CustosVirginum — Administration"),
      ((function()
        if error_msg then
          return H.div({
            class = "flash error"
          }, error_msg)
        else
          return ""
        end
      end)()),
      H.form({
        method = "POST",
        action = "/admin/login"
      }, H.label("Utilisateur")),
      H.input({
        name = "user",
        type = "text",
        required = true
      }),
      H.label("Mot de passe"),
      H.input({
        name = "password",
        type = "password",
        required = true
      }),
      H.button({
        type = "submit"
      }, "Connexion")
    })
  })
end
local handle_login_get
handle_login_get = function(req, state)
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, login_page(nil)
end
local handle_login_post
handle_login_post = function(req, state)
  local parse_form
  parse_form = function(body)
    if not (body) then
      return { }
    end
    local out = { }
    for k, v in (body or ""):gmatch("([^&=]+)=([^&]*)") do
      local dec
      dec = function(s)
        return (s:gsub("%%(%x%x)", function(h)
          return string.char(tonumber(h, 16))
        end)):gsub("+", " ")
      end
      out[dec(k)] = dec(v)
    end
    return out
  end
  local form = parse_form(req.body)
  local user = form.user
  local pass = form.password
  if not (user and pass) then
    return 400, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, login_page("Identifiants manquants")
  end
  local stored = state.secrets and state.secrets[user]
  if not (stored) then
    return 401, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, login_page("Identifiants invalides")
  end
  local ok, _ = verify_password(pass, stored)
  if not (ok) then
    return 401, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, login_page("Identifiants invalides")
  end
  local idle_timeout = state.auth_cfg and state.auth_cfg.session_ttl or 3600
  if idle_timeout == 0 then
    idle_timeout = 3600
  end
  local now = os.time()
  local tok = token.generate("admin", user, "", now + idle_timeout, state.token_key)
  return 302, {
    ["Location"] = "/admin/",
    ["Set-Cookie"] = make_admin_cookie(tok)
  }, ""
end
local handle_logout
handle_logout = function(req, state)
  return 302, {
    ["Location"] = "/admin/login",
    ["Set-Cookie"] = clear_admin_cookie()
  }, ""
end
return {
  check_admin_session = check_admin_session,
  handle_login_get = handle_login_get,
  handle_login_post = handle_login_post,
  handle_logout = handle_logout
}
