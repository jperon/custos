local ffi = require("ffi")
ffi.cdef([[  typedef int pid_t;
  pid_t getppid(void);
  int kill(pid_t pid, int sig);
]])
local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local token = require("auth.token")
local add_session, purge_expired, load_sessions, write_sessions
do
  local _obj_0 = require("auth.sessions")
  add_session, purge_expired, load_sessions, write_sessions = _obj_0.add_session, _obj_0.purge_expired, _obj_0.load_sessions, _obj_0.write_sessions
end
local verify_password, register_user, update_user_hash
do
  local _obj_0 = require("auth.credentials")
  verify_password, register_user, update_user_hash = _obj_0.verify_password, _obj_0.register_user, _obj_0.update_user_hash
end
local page, success_page, css_content
do
  local _obj_0 = require("auth.pages")
  page, success_page, css_content = _obj_0.page, _obj_0.success_page, _obj_0.css_content
end
local H = require("auth.html")
local refresh_rule_auth_sets, delete_rule_auth_sets, refresh_nft
do
  local _obj_0 = require("auth.nft_auth_sets")
  refresh_rule_auth_sets, delete_rule_auth_sets, refresh_nft = _obj_0.refresh_rule_auth_sets, _obj_0.delete_rule_auth_sets, _obj_0.refresh_nft
end
local SIGHUP = 1
local COOKIE_NAME = "custos_session"
local make_session_cookie
make_session_cookie = function(tok)
  return tostring(COOKIE_NAME) .. "=" .. tostring(tok) .. "; Path=/; HttpOnly; SameSite=Strict"
end
local clear_session_cookie
clear_session_cookie = function()
  return tostring(COOKIE_NAME) .. "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
end
local signal_parent_reload
signal_parent_reload = function()
  local parent_pid = tonumber(ffi.C.getppid())
  if parent_pid <= 0 then
    return false
  end
  local rc = ffi.C.kill(parent_pid, SIGHUP)
  return rc == 0
end
local url_decode
url_decode = function(s)
  if not (s) then
    return ""
  end
  s = s:gsub("+", " ")
  return s:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end)
end
local parse_form
parse_form = function(body)
  local out = { }
  if not (body) then
    return out
  end
  for k, v in body:gmatch("([^&=]+)=([^&]*)") do
    out[url_decode(k)] = url_decode(v)
  end
  return out
end
local register_form_page
register_form_page = function(req)
  return page({
    H.form({
      method = "POST",
      action = "/register"
    }, H.label("Utilisateur ", H.input({
      name = "user",
      type = "text"
    }), H.br()), H.label("Mot de passe ", H.input({
      name = "password",
      type = "password"
    }), H.br()), H.button({
      type = "submit"
    }, "S'inscrire")),
    H.a({
      href = "/"
    }, "Déjà un compte ? Se connecter")
  })
end
local register_success_page
register_success_page = function(req)
  return page({
    H.p("Compte créé. Vous pouvez maintenant vous connecter."),
    H.a({
      href = "/"
    }, "Se connecter")
  })
end
local login_page
login_page = function()
  return page({
    H.form({
      method = "POST",
      action = "/login"
    }, H.label("Utilisateur ", H.input({
      name = "user",
      type = "text"
    }), H.br()), H.label("Mot de passe ", H.input({
      name = "password",
      type = "password"
    }), H.br()), H.button({
      type = "submit"
    }, "Connexion")),
    H.a({
      href = "/register"
    }, "Inscription")
  })
end
local handle_login
handle_login = function(req, peer_ip, peer_mac, state)
  local form = parse_form(req.body)
  local user = form.user
  local pass = form.password
  if not (user and pass) then
    return 400, { }, "Missing credentials"
  end
  local stored = state.secrets and state.secrets[user]
  if not (stored) then
    return 401, { }, "Invalid credentials"
  end
  local ok, needs_rehash = verify_password(pass, stored)
  if not (ok) then
    return 401, { }, "Invalid credentials"
  end
  if needs_rehash and state.secrets_path then
    local rh_ok, rh_err = update_user_hash(user, pass, state.secrets_path)
    if rh_ok then
      log_info(function()
        return {
          action = "credentials_rehashed",
          user = user
        }
      end)
    else
      log_warn(function()
        return {
          action = "credentials_rehash_failed",
          user = user,
          err = tostring(rh_err)
        }
      end)
    end
  end
  local sessions = load_sessions(state.sessions_file)
  purge_expired(sessions)
  local mac = peer_mac
  if not (mac and mac ~= "unknown") then
    log_warn(function()
      return {
        action = "server_login_mac_missing",
        ip = peer_ip,
        mac = mac
      }
    end)
    return 401, { }, "Unable to identify client MAC (IP: " .. tostring(peer_ip) .. ")"
  end
  log_info(function()
    return {
      action = "server_login_success",
      user = user,
      mac = mac,
      ip = peer_ip
    }
  end)
  local idle_timeout = state.auth_cfg.idle_timeout or 300
  local now = os.time()
  local session_expires = now + idle_timeout
  local token_expires = session_expires
  add_session(sessions, mac, peer_ip, user, session_expires)
  local err
  ok, err = write_sessions(sessions, state.sessions_file)
  if not (ok) then
    log_warn(function()
      return {
        action = "server_sessions_write_failed",
        path = state.sessions_file,
        err = err
      }
    end)
    return 500, { }, "Session persistence failed"
  end
  log_info(function()
    return {
      action = "server_sessions_write_success",
      path = state.sessions_file,
      mac = mac
    }
  end)
  if state.nft_sess then
    ok, err = pcall(function()
      return refresh_rule_auth_sets(state.nft_sess, peer_ip, mac, state.auth_cfg.idle_timeout, user)
    end)
    if not (ok) then
      log_warn(function()
        return {
          action = "server_nft_refresh_failed",
          peer = peer_ip,
          mac = mac,
          err = tostring(err)
        }
      end)
    end
  else
    log_warn(function()
      return {
        action = "server_nft_sess_missing",
        peer = peer_ip,
        mac = mac
      }
    end)
  end
  local tok = token.generate("user", user, mac, token_expires, state.token_key)
  local admin_users = state.admin_users or { }
  local user_in_admin = false
  for _, u in ipairs(admin_users) do
    if u == user then
      user_in_admin = true
    end
  end
  local is_admin = (state.admin_allow_all_when_empty and #admin_users == 0) or user_in_admin
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8",
    ["Set-Cookie"] = make_session_cookie(tok)
  }, success_page(state.auth_cfg, now, is_admin)
end
local handle_ping
handle_ping = function(req, peer_ip, peer_mac, state)
  log_info(function()
    return {
      action = "server_ping_received",
      peer_ip = peer_ip,
      peer_mac = peer_mac
    }
  end)
  local cookie_val = token.get_cookie(req.headers.cookie or "", COOKIE_NAME)
  local p, tok_err = token.verify(cookie_val, state.token_key)
  if not (p) then
    log_info(function()
      return {
        action = "server_ping_token_invalid",
        peer_ip = peer_ip,
        err = tok_err
      }
    end)
    return 401, { }, ""
  end
  local user = p.user
  local mac = p.mac
  local idle_timeout = state.auth_cfg.idle_timeout or 300
  local now = os.time()
  local session_expires = now + idle_timeout
  local token_expires = session_expires
  local sessions = load_sessions(state.sessions_file)
  purge_expired(sessions)
  if mac and mac ~= "unknown" and not sessions[mac:lower()] then
    log_info(function()
      return {
        action = "server_ping_session_invalidated",
        peer_ip = peer_ip,
        mac = mac
      }
    end)
    return 401, { }, ""
  end
  add_session(sessions, mac, peer_ip, user, session_expires)
  write_sessions(sessions, state.sessions_file)
  refresh_nft(state.nft_sess, peer_ip, mac, idle_timeout, user)
  local new_tok = token.generate("user", user, mac, token_expires, state.token_key)
  log_info(function()
    return {
      action = "server_ping_success",
      peer_mac = mac
    }
  end)
  return 204, {
    ["Set-Cookie"] = make_session_cookie(new_tok)
  }, ""
end
local handle_logout
handle_logout = function(req, peer_ip, peer_mac, state)
  local cookie_val = token.get_cookie(req.headers.cookie or "", COOKIE_NAME)
  local p = (token.verify(cookie_val, state.token_key))
  local mac = (p and p.mac) or peer_mac
  local user = p and p.user
  if mac and mac ~= "unknown" then
    local sessions = load_sessions(state.sessions_file)
    sessions[mac:lower()] = nil
    write_sessions(sessions, state.sessions_file)
  end
  if state.nft_sess then
    state.nft_sess.del_authenticated(peer_ip)
    if mac and mac ~= "unknown" then
      state.nft_sess.del_authenticated_mac(mac)
    end
  end
  if user and state.nft_sess then
    delete_rule_auth_sets(state.nft_sess, peer_ip, mac, user)
  end
  return 302, {
    ["Location"] = "/",
    ["Set-Cookie"] = clear_session_cookie()
  }, ""
end
local handle_register
handle_register = function(req, peer_ip, peer_mac, state)
  local form = parse_form(req.body)
  local user = form.user
  local pass = form.password
  if not (user and pass) then
    return 400, { }, "Missing credentials"
  end
  local new_secrets, err = register_user(user, pass, state.secrets_path, state.secrets)
  if not (new_secrets) then
    if err and err:match("déjà") then
      return 409, { }, err
    end
    return 500, { }, err or "Registration failed"
  end
  state.secrets = new_secrets
  if not signal_parent_reload() then
    log_warn(function()
      return {
        action = "server_reload_signal_failed",
        parent_pid = tonumber(ffi.C.getppid())
      }
    end)
  end
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, register_success_page(req)
end
local handle_request
handle_request = function(req, peer_ip, peer_mac, state)
  log_info(function()
    return {
      action = "server_request_received",
      path = req.path,
      method = req.method,
      peer_ip = peer_ip,
      peer_mac = peer_mac
    }
  end)
  if req.path == "/" and req.method == "GET" then
    return 200, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, login_page()
  elseif req.path == "/css" and req.method == "GET" then
    return 200, {
      ["Content-Type"] = "text/css"
    }, css_content
  elseif req.path == "/login" and req.method == "POST" then
    log_info(function()
      return {
        action = "server_routing_to_handle_login",
        path = req.path,
        method = req.method
      }
    end)
    return handle_login(req, peer_ip, peer_mac, state)
  elseif req.path == "/ping" and req.method == "GET" then
    return handle_ping(req, peer_ip, peer_mac, state)
  elseif req.path == "/logout" then
    return handle_logout(req, peer_ip, peer_mac, state)
  elseif req.path == "/register" and req.method == "GET" then
    return 200, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, register_form_page(req)
  elseif req.path == "/register" and req.method == "POST" then
    return handle_register(req, peer_ip, peer_mac, state)
  elseif req.path:match("^/admin") then
    local webui_router = require("webui.router")
    return webui_router.dispatch(req, state)
  else
    return 302, {
      ["Location"] = "/"
    }, ""
  end
end
return {
  make_session_cookie = make_session_cookie,
  clear_session_cookie = clear_session_cookie,
  signal_parent_reload = signal_parent_reload,
  url_decode = url_decode,
  parse_form = parse_form,
  register_form_page = register_form_page,
  register_success_page = register_success_page,
  login_page = login_page,
  handle_login = handle_login,
  handle_ping = handle_ping,
  handle_logout = handle_logout,
  handle_register = handle_register,
  handle_request = handle_request,
  COOKIE_NAME = COOKIE_NAME
}
