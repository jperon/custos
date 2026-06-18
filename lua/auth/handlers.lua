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
local verify_password, verify_response, register_user, set_record, parse_record, valid_username
do
  local _obj_0 = require("auth.credentials")
  verify_password, verify_response, register_user, set_record, parse_record, valid_username = _obj_0.verify_password, _obj_0.verify_response, _obj_0.register_user, _obj_0.set_record, _obj_0.parse_record, _obj_0.valid_username
end
local make_nonce, verify_nonce, salt_iter_for
do
  local _obj_0 = require("auth.challenge")
  make_nonce, verify_nonce, salt_iter_for = _obj_0.make_nonce, _obj_0.verify_nonce, _obj_0.salt_iter_for
end
local page, success_page, css_content, password_page, password_changed_page, CRYPTO_JS, LOGIN_JS, REGISTER_JS
do
  local _obj_0 = require("auth.pages")
  page, success_page, css_content, password_page, password_changed_page, CRYPTO_JS, LOGIN_JS, REGISTER_JS = _obj_0.page, _obj_0.success_page, _obj_0.css_content, _obj_0.password_page, _obj_0.password_changed_page, _obj_0.CRYPTO_JS, _obj_0.LOGIN_JS, _obj_0.REGISTER_JS
end
local H = require("auth.html")
local delete_rule_auth_sets, refresh_nft
do
  local _obj_0 = require("auth.nft_auth_sets")
  delete_rule_auth_sets, refresh_nft = _obj_0.delete_rule_auth_sets, _obj_0.refresh_nft
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
local notify_reload
notify_reload = function(state)
  local fn = (state and state.notify_reload) or signal_parent_reload
  return fn()
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
      id = "register-form",
      method = "POST",
      action = "/register"
    }, H.label("Utilisateur ", H.input({
      name = "user",
      type = "text"
    }), H.br()), H.label("Mot de passe ", H.input({
      name = "password",
      type = "password",
      autocomplete = "new-password"
    }), H.br()), H.button({
      type = "submit"
    }, "S'inscrire")),
    H.a({
      href = "/"
    }, "Déjà un compte ? Se connecter"),
    H.script(CRYPTO_JS .. REGISTER_JS)
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
      id = "login-form",
      method = "POST",
      action = "/login"
    }, H.label("Utilisateur ", H.input({
      name = "user",
      type = "text",
      autocomplete = "username"
    }), H.br()), H.label("Mot de passe ", H.input({
      name = "password",
      type = "password",
      autocomplete = "current-password"
    }), H.br()), H.button({
      type = "submit"
    }, "Connexion")),
    H.a({
      href = "/register"
    }, "Inscription"),
    H.script(CRYPTO_JS .. LOGIN_JS)
  })
end
local handle_challenge
handle_challenge = function(req, peer_ip, peer_mac, state)
  local form = parse_form(req.body)
  local user = form.user
  if not (user) then
    local cookie_val = token.get_cookie(req.headers.cookie or "", COOKIE_NAME)
    local p = token.verify(cookie_val, state.token_key)
    user = p and p.user
  end
  if not (user) then
    return 400, { }, "Missing user"
  end
  local nonce = make_nonce(state.token_key, peer_mac, state.auth_cfg and state.auth_cfg.challenge_ttl)
  local si = salt_iter_for(state.secrets, state.token_key, user)
  local body = "{\"nonce\":\"" .. tostring(nonce) .. "\",\"salt\":\"" .. tostring(si.salt) .. "\",\"iter\":" .. tostring(si.iter) .. "}"
  return 200, {
    ["Content-Type"] = "application/json"
  }, body
end
local plaintext_allowed
plaintext_allowed = function(state)
  local v = state.auth_cfg and state.auth_cfg.allow_plaintext_login
  if v == nil then
    return true
  else
    return v and true or false
  end
end
local is_admin_user
is_admin_user = function(state, user)
  local admin_users = state.admin_users or { }
  for _, u in ipairs(admin_users) do
    if u == user then
      return true
    end
  end
  return state.admin_allow_all_when_empty and #admin_users == 0
end
local handle_login
handle_login = function(req, peer_ip, peer_mac, state)
  local form = parse_form(req.body)
  local user = form.user
  local nonce = form.nonce
  local response = form.response
  local pass = form.password
  if not (user and ((nonce and response) or pass)) then
    return 400, { }, "Missing credentials"
  end
  local stored = state.secrets and state.secrets[user]
  if nonce and response then
    local nok, nerr = verify_nonce(state.token_key, peer_mac, nonce)
    if not (nok) then
      log_warn(function()
        return {
          action = "server_login_nonce_rejected",
          user = user,
          ip = peer_ip,
          err = nerr
        }
      end)
      return 401, { }, "Invalid credentials"
    end
    if not (verify_response(stored, nonce, response)) then
      return 401, { }, "Invalid credentials"
    end
  else
    if not (plaintext_allowed(state)) then
      log_warn(function()
        return {
          action = "server_login_plaintext_refused",
          user = user,
          ip = peer_ip
        }
      end)
      return 401, { }, "Invalid credentials"
    end
    if not (stored and verify_password(pass, stored)) then
      return 401, { }, "Invalid credentials"
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
  local ok, err = write_sessions(sessions, state.sessions_file)
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
      return refresh_nft(state.nft_sess, peer_ip, mac, state.auth_cfg.idle_timeout, user)
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
  local is_admin = is_admin_user(state, user)
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
  local p, tok_err, expired_p = token.verify(cookie_val, state.token_key)
  if not (p) then
    if expired_p and expired_p.mac and expired_p.mac ~= "unknown" then
      local sessions = load_sessions(state.sessions_file)
      purge_expired(sessions)
      if sessions[expired_p.mac:lower()] then
        log_info(function()
          return {
            action = "server_ping_stale_token_session_alive",
            peer_ip = peer_ip,
            mac = expired_p.mac
          }
        end)
        return 204, { }, ""
      end
    end
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
local handle_bye
handle_bye = function(req, peer_ip, peer_mac, state)
  local cookie_val = token.get_cookie(req.headers.cookie or "", COOKIE_NAME)
  local p = (token.verify(cookie_val, state.token_key))
  local mac = (p and p.mac) or peer_mac
  local user = p and p.user
  local grace = state.auth_cfg.close_grace or 45
  local now = os.time()
  if mac and mac ~= "unknown" then
    local sessions = load_sessions(state.sessions_file)
    local s = sessions[mac:lower()]
    if s then
      local capped = now + grace
      if not s.expires or s.expires > capped then
        s.expires = capped
        write_sessions(sessions, state.sessions_file)
        if state.nft_sess then
          refresh_nft(state.nft_sess, peer_ip, mac, grace, user or s.user)
        end
        log_info(function()
          return {
            action = "server_bye_grace",
            mac = mac,
            grace = grace
          }
        end)
      end
    end
  end
  return 204, { }, ""
end
local json_escape
json_escape = function(s)
  if not (s) then
    return ""
  end
  s = tostring(s)
  s = s:gsub("\\", "\\\\")
  s = s:gsub("\"", "\\\"")
  s = s:gsub("\n", "\\n")
  s = s:gsub("\r", "\\r")
  s = s:gsub("\t", "\\t")
  return s
end
local REFUSALS_MAX = 50
local handle_refusals
handle_refusals = function(req, peer_ip, peer_mac, state)
  local cookie_val = token.get_cookie(req.headers.cookie or "", COOKIE_NAME)
  local p = token.verify(cookie_val, state.token_key)
  if not (p) then
    return 401, { }, ""
  end
  local mac = p.mac
  if not (mac and mac ~= "unknown") then
    return 200, {
      ["Content-Type"] = "application/json"
    }, "[]"
  end
  local mac_lc = mac:lower()
  local events_dir = state.events_dir or "/tmp/custos/events"
  local fh = io.open(tostring(events_dir) .. "/recent-verdicts.tsv", "r")
  if not (fh) then
    return 200, {
      ["Content-Type"] = "application/json"
    }, "[]"
  end
  local parts = { }
  for line in fh:lines() do
    local _continue_0 = false
    repeat
      if #parts >= REFUSALS_MAX then
        break
      end
      local l_mac, _ip, _user, qname, decision, reason, count, _first_ts, ts = line:match("^([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)$")
      if not (l_mac and l_mac:lower() == mac_lc) then
        _continue_0 = true
        break
      end
      if not (decision == "block") then
        _continue_0 = true
        break
      end
      parts[#parts + 1] = "{\"qname\":\"" .. tostring(json_escape(qname)) .. "\",\"reason\":\"" .. tostring(json_escape(reason)) .. "\",\"count\":" .. tostring(tonumber(count) or 0) .. ",\"ts\":" .. tostring(tonumber(ts) or 0) .. "}"
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  fh:close()
  return 200, {
    ["Content-Type"] = "application/json"
  }, "[" .. tostring(table.concat(parts, ",")) .. "]"
end
local handle_register
handle_register = function(req, peer_ip, peer_mac, state)
  local form = parse_form(req.body)
  local user = form.user
  local salt = form.salt
  local iter = tonumber(form.iter)
  local hash = form.hash
  local pass = form.password
  if user and salt and iter and hash then
    if not (valid_username(user)) then
      return 400, { }, "Adresse de courriel invalide."
    end
    if state.secrets and state.secrets[user] then
      return 409, { }, "Ce nom d'utilisateur est déjà pris."
    end
    local record = "pbkdf2-sha256:" .. tostring(iter) .. ":" .. tostring(salt) .. ":" .. tostring(hash)
    if not (parse_record(record)) then
      return 400, { }, "Invalid record"
    end
    local ok, err = set_record(user, record, state.secrets_path)
    if not (ok) then
      return 500, { }, err or "Registration failed"
    end
    state.secrets = state.secrets or { }
    state.secrets[user] = record
  else
    if not (user and pass) then
      return 400, { }, "Missing credentials"
    end
    if not (plaintext_allowed(state)) then
      return 401, { }, "Plaintext registration disabled"
    end
    local new_secrets, err = register_user(user, pass, state.secrets_path, state.secrets)
    if not (new_secrets) then
      if err and err:match("déjà") then
        return 409, { }, err
      end
      return 500, { }, err or "Registration failed"
    end
    state.secrets = new_secrets
  end
  if not notify_reload(state) then
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
local handle_password_change
handle_password_change = function(req, peer_ip, peer_mac, state)
  local cookie_val = token.get_cookie(req.headers.cookie or "", COOKIE_NAME)
  local p = token.verify(cookie_val, state.token_key)
  if not (p and p.user) then
    return 401, { }, "Authentication required"
  end
  local user = p.user
  local form = parse_form(req.body)
  local nonce = form.nonce
  local response = form.response
  local salt = form.salt
  local iter = tonumber(form.iter)
  local hash = form.hash
  if not (nonce and response and salt and iter and hash) then
    return 400, { }, "Missing fields"
  end
  local nok = verify_nonce(state.token_key, peer_mac, nonce)
  if not (nok) then
    return 401, { }, "Invalid credentials"
  end
  local stored = state.secrets and state.secrets[user]
  if not (verify_response(stored, nonce, response)) then
    return 401, { }, "Invalid credentials"
  end
  local record = "pbkdf2-sha256:" .. tostring(iter) .. ":" .. tostring(salt) .. ":" .. tostring(hash)
  if not (parse_record(record)) then
    return 400, { }, "Invalid record"
  end
  local ok, err = set_record(user, record, state.secrets_path)
  if not (ok) then
    log_warn(function()
      return {
        action = "server_password_change_failed",
        user = user,
        err = tostring(err)
      }
    end)
    return 500, { }, "Password change failed"
  end
  if state.secrets then
    state.secrets[user] = record
  end
  notify_reload(state)
  log_info(function()
    return {
      action = "server_password_changed",
      user = user
    }
  end)
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, password_changed_page()
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
    local cookie_val = token.get_cookie(req.headers.cookie or "", COOKIE_NAME)
    local p = token.verify(cookie_val, state.token_key)
    if p and p.user and p.mac and p.mac ~= "unknown" then
      local sessions = load_sessions(state.sessions_file)
      purge_expired(sessions)
      if sessions[p.mac:lower()] then
        local is_admin = is_admin_user(state, p.user)
        local body = success_page(state.auth_cfg, os.time(), is_admin)
        return 200, {
          ["Content-Type"] = "text/html; charset=UTF-8"
        }, body
      end
    end
    return 200, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, login_page()
  elseif req.path == "/css" and req.method == "GET" then
    return 200, {
      ["Content-Type"] = "text/css"
    }, css_content
  elseif req.path == "/challenge" and req.method == "POST" then
    return handle_challenge(req, peer_ip, peer_mac, state)
  elseif req.path == "/login" and req.method == "POST" then
    log_info(function()
      return {
        action = "server_routing_to_handle_login",
        path = req.path,
        method = req.method
      }
    end)
    return handle_login(req, peer_ip, peer_mac, state)
  elseif req.path == "/password" and req.method == "GET" then
    local cookie_val = token.get_cookie(req.headers.cookie or "", COOKIE_NAME)
    local p = token.verify(cookie_val, state.token_key)
    if not (p and p.user) then
      return 302, {
        ["Location"] = "/"
      }, ""
    end
    return 200, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, password_page()
  elseif req.path == "/password" and req.method == "POST" then
    return handle_password_change(req, peer_ip, peer_mac, state)
  elseif req.path == "/ping" and req.method == "GET" then
    return handle_ping(req, peer_ip, peer_mac, state)
  elseif req.path == "/refusals" and req.method == "GET" then
    return handle_refusals(req, peer_ip, peer_mac, state)
  elseif req.path == "/logout" then
    return handle_logout(req, peer_ip, peer_mac, state)
  elseif req.path == "/bye" then
    return handle_bye(req, peer_ip, peer_mac, state)
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
  handle_bye = handle_bye,
  handle_register = handle_register,
  handle_request = handle_request,
  handle_refusals = handle_refusals,
  handle_challenge = handle_challenge,
  handle_password_change = handle_password_change,
  COOKIE_NAME = COOKIE_NAME
}
