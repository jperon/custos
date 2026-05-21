local socket = require("lib.socket")
local ssl = require("auth.ffi_wolfssl")
local ffi = require("ffi")
local fork_child, reap_one
do
  local _obj_0 = require("lib.process")
  fork_child, reap_one = _obj_0.fork_child, _obj_0.reap_one
end
local session_for_mac, add_session, purge_expired, load_sessions, write_sessions
do
  local _obj_0 = require("auth.sessions")
  session_for_mac, add_session, purge_expired, load_sessions, write_sessions = _obj_0.session_for_mac, _obj_0.add_session, _obj_0.purge_expired, _obj_0.load_sessions, _obj_0.write_sessions
end
local verify_password, register_user, update_user_hash
do
  local _obj_0 = require("auth.credentials")
  verify_password, register_user, update_user_hash = _obj_0.verify_password, _obj_0.register_user, _obj_0.update_user_hash
end
local token = require("auth.token")
local load_or_generate_sni, load_static
do
  local _obj_0 = require("auth.cert")
  load_or_generate_sni, load_static = _obj_0.load_or_generate_sni, _obj_0.load_static
end
local extract_sni
extract_sni = require("auth.sni_extractor").extract_sni
local log_info, log_warn, log_error, log_debug
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error, log_debug = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error, _obj_0.log_debug
end
local config = require("config")
local read_request, send_response
do
  local _obj_0 = require("lib.http")
  read_request, send_response = _obj_0.read_request, _obj_0.send_response
end
local get_mac
get_mac = require("mac_learner_ipc").get_mac
ffi.cdef([[  typedef int pid_t;
  pid_t getppid(void);
  int kill(pid_t pid, int sig);
]])
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
local H = require("auth.html")
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
local page
page = function(self)
  return "<!DOCTYPE html>\n" .. H.html({
    lang = "fr",
    H.head({
      H.meta({
        charset = "UTF-8"
      }),
      H.title("CustosVirginum"),
      H.link({
        rel = "stylesheet",
        href = "/css"
      }),
      H.link({
        rel = "icon",
        href = "data:image/svg+xml,<svg viewBox='0 0 100 100'><text y='75' font-size='75'>✞</text></svg>"
      })
    }),
    H.body(self)
  })
end
local success_page
success_page = function(auth_cfg, created_at)
  local interval = tonumber(auth_cfg and auth_cfg.heartbeat_interval) or 30
  if interval <= 0 then
    interval = 30
  end
  local idle_timeout = tonumber(auth_cfg and auth_cfg.idle_timeout) or 90
  local session_start = tonumber(created_at) or 0
  return page({
    H.p("Connexion réussie. Votre accès est actif tant que cette fenêtre est ouverte."),
    H.p({
      id = "session-timer"
    }, "Session ouverte depuis : --"),
    H.p(H.a({
      href = "/logout"
    }, "Déconnexion")),
    H.script("\n      var iv = " .. tostring(interval) .. " * 1000;\n      var idle = " .. tostring(idle_timeout) .. " * 1000;\n      var sessionStart = " .. tostring(session_start) .. ";\n      var lastSuccess = Date.now();\n      function ping(){\n        fetch('/ping',{method:'GET',credentials:'omit'})\n          .then(function(r){\n            lastSuccess = Date.now();\n            if(r.status===401){\n              if(document.visibilityState!=='visible')\n                alert('Connexion perdue, veuillez vous authentifier de nouveau.');\n              location.href='/';\n            }\n          })\n          .catch(function(){\n            if (Date.now() - lastSuccess > idle) {\n              if (document.visibilityState === 'visible') location.href='/';\n            }\n          });\n      }\n      function updateTimer(){\n        var now = Math.floor(Date.now() / 1000);\n        var elapsed = now - sessionStart;\n        if (elapsed < 0) elapsed = 0;\n        var h = Math.floor(elapsed / 3600);\n        var m = Math.floor((elapsed % 3600) / 60);\n        var txt;\n        if (h > 0) {\n          txt = h + 'h ' + (m < 10 ? '0' : '') + m + 'min';\n        } else {\n          txt = m + ' min';\n        }\n        var el = document.getElementById('session-timer');\n        if (el) el.textContent = 'Session ouverte depuis : ' + txt;\n      }\n      setInterval(ping, iv);\n      setInterval(updateTimer, 10000);\n      ping();\n      updateTimer();\n      // Envoyer un ping immédiat au retour en foreground (anti-throttling navigateur).\n      document.addEventListener('visibilitychange', function(){\n        if (document.visibilityState === 'visible') ping();\n      });\n      // Déconnexion explicite à la fermeture du navigateur / de l'onglet.\n      // sendBeacon est envoyé de manière garantie même pendant le déchargement.\n      // pagehide est plus fiable que beforeunload sur mobile (iOS Safari).\n      // On ne déconnecte pas si la page est mise en BFCache (event.persisted).\n      function logout(){\n        if (navigator.sendBeacon) {\n          navigator.sendBeacon('/logout');\n        } else {\n          fetch('/logout', {method:'GET', keepalive:true, credentials:'omit'});\n        }\n      }\n      window.addEventListener('pagehide', function(e){\n        if (!e.persisted) logout();\n      });\n    ")
  })
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
local sanitize_id
sanitize_id = function(raw)
  local s = tostring(raw):lower()
  s = s:gsub("[^a-z0-9_%-]+", "_")
  s = s:gsub("_+", "_")
  s = s:gsub("^_+", "")
  s = s:gsub("_+$", "")
  s = s:gsub("%-+", "_")
  if #s > 40 then
    s = s:sub(1, 40)
  end
  return s
end
local rule_id = require("filter.rule_id")
local generate_rule_id = rule_id.generate
local rule_requires_auth
rule_requires_auth = function(rule)
  if not (rule and rule.conditions) then
    return false
  end
  local conditions = rule.conditions
  local is_array_format = type(conditions[1]) == "table"
  if is_array_format then
    for _, cond in ipairs(conditions) do
      local _continue_0 = false
      repeat
        if not (type(cond) == "table") then
          _continue_0 = true
          break
        end
        for k, _ in pairs(cond) do
          if k == "from_users" or k == "from_userlists" then
            return true
          end
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
  else
    for k, _ in pairs(conditions) do
      if k == "from_users" or k == "from_userlists" then
        return true
      end
    end
  end
  return false
end
local user_qualifies_for_rule
user_qualifies_for_rule = function(user, rule)
  if not (rule and rule.conditions) then
    return false
  end
  local filter_cfg = config.filter or { }
  local userlists_cfg = filter_cfg.userlists or { }
  local conditions = rule.conditions
  local is_array_format = type(conditions[1]) == "table"
  if is_array_format then
    for _, cond in ipairs(conditions) do
      local _continue_0 = false
      repeat
        if not (type(cond) == "table") then
          _continue_0 = true
          break
        end
        for k, v in pairs(cond) do
          if k == "from_users" then
            local users_list
            if type(v) == "table" then
              users_list = v
            else
              users_list = {
                v
              }
            end
            for _, allowed_user in ipairs(users_list) do
              if tostring(allowed_user) == tostring(user) then
                return true
              end
            end
            return false
          end
          if k == "from_userlists" then
            local list_names
            if type(v) == "table" then
              list_names = v
            else
              list_names = {
                v
              }
            end
            for _, list_name in ipairs(list_names) do
              local list_users = userlists_cfg[list_name] or { }
              for _, allowed_user in ipairs(list_users) do
                if tostring(allowed_user) == tostring(user) then
                  return true
                end
              end
            end
            return false
          end
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
  else
    for k, v in pairs(conditions) do
      if k == "from_users" then
        local users_list
        if type(v) == "table" then
          users_list = v
        else
          users_list = {
            v
          }
        end
        for _, allowed_user in ipairs(users_list) do
          if tostring(allowed_user) == tostring(user) then
            return true
          end
        end
        return false
      end
      if k == "from_userlists" then
        local list_names
        if type(v) == "table" then
          list_names = v
        else
          list_names = {
            v
          }
        end
        for _, list_name in ipairs(list_names) do
          local list_users = userlists_cfg[list_name] or { }
          for _, allowed_user in ipairs(list_users) do
            if tostring(allowed_user) == tostring(user) then
              return true
            end
          end
        end
        return false
      end
    end
  end
  return true
end
local refresh_nft
refresh_nft = function(nft_sess, ip, mac, ttl, user)
  if not (nft_sess) then
    return 
  end
  if ip and ip ~= "unknown" then
    nft_sess.add_authenticated(ip, ttl)
  end
  if mac and mac ~= "unknown" then
    nft_sess.add_authenticated_mac(mac, ttl)
  end
  local filter_cfg = config.filter or { }
  local rules = filter_cfg.rules or { }
  for idx, rule in ipairs(rules) do
    local _continue_0 = false
    repeat
      local requires_auth = rule_requires_auth(rule)
      if not (requires_auth) then
        _continue_0 = true
        break
      end
      local qualifies = user_qualifies_for_rule(user, rule)
      if not (qualifies) then
        _continue_0 = true
        break
      end
      rule_id = generate_rule_id(rule, idx)
      local ok, err = pcall(function()
        if nft_sess then
          nft_sess.run_nft("add element bridge dns-filter-bridge " .. tostring(rule_id) .. "_auth_mac { " .. tostring(mac) .. " timeout " .. tostring(ttl) .. "s }", {
            quiet = true
          })
          if ip and ip ~= "unknown" then
            if ip:find(":") then
              return nft_sess.run_nft("add element bridge dns-filter-bridge " .. tostring(rule_id) .. "_auth_ip6 { " .. tostring(ip) .. " timeout " .. tostring(ttl) .. "s }", {
                quiet = true
              })
            else
              return nft_sess.run_nft("add element bridge dns-filter-bridge " .. tostring(rule_id) .. "_auth_ip4 { " .. tostring(ip) .. " timeout " .. tostring(ttl) .. "s }", {
                quiet = true
              })
            end
          end
        end
      end)
      if not (ok) then
        log_warn({
          action = "auth_set_add_failed",
          rule_id = rule_id,
          mac = mac,
          ip = ip,
          err = tostring(err)
        })
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
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
      log_info({
        action = "credentials_rehashed",
        user = user
      })
    else
      log_warn({
        action = "credentials_rehash_failed",
        user = user,
        err = tostring(rh_err)
      })
    end
  end
  local sessions = load_sessions(state.sessions_file)
  purge_expired(sessions)
  local mac = peer_mac
  if not (mac and mac ~= "unknown") then
    log_warn({
      action = "server_login_mac_missing",
      ip = peer_ip,
      mac = mac
    })
    return 401, { }, "Unable to identify client MAC (IP: " .. tostring(peer_ip) .. ")"
  end
  log_info({
    action = "server_login_success",
    user = user,
    mac = mac,
    ip = peer_ip
  })
  local idle_timeout = state.auth_cfg.idle_timeout or 120
  local now = os.time()
  add_session(sessions, mac, peer_ip, user, now + idle_timeout)
  local err
  ok, err = write_sessions(sessions, state.sessions_file)
  if not (ok) then
    log_warn({
      action = "server_sessions_write_failed",
      path = state.sessions_file,
      err = err
    })
    return 500, { }, "Session persistence failed"
  end
  log_info({
    action = "server_sessions_write_success",
    path = state.sessions_file,
    mac = mac
  })
  if state.nft_sess then
    ok, err = pcall(function()
      return refresh_nft(state.nft_sess, peer_ip, mac, state.auth_cfg.idle_timeout, user)
    end)
    if not (ok) then
      log_warn({
        action = "server_nft_refresh_failed",
        peer = peer_ip,
        mac = mac,
        err = tostring(err)
      })
    end
  else
    log_warn({
      action = "server_nft_sess_missing",
      peer = peer_ip,
      mac = mac
    })
  end
  local filter_cfg = config.filter or { }
  local rules = filter_cfg.rules or { }
  for idx, rule in ipairs(rules) do
    local _continue_0 = false
    repeat
      local requires_auth = rule_requires_auth(rule)
      local qualifies = user_qualifies_for_rule(user, rule)
      log_info({
        action = "server_rule_check",
        idx = idx,
        description = rule.description,
        requires_auth = requires_auth,
        qualifies = qualifies,
        user = user
      })
      if not (requires_auth) then
        _continue_0 = true
        break
      end
      if not (qualifies) then
        _continue_0 = true
        break
      end
      rule_id = generate_rule_id(rule, idx)
      log_info({
        action = "server_rule_id_generated",
        rule_id = rule_id,
        description = rule.description
      })
      ok, err = pcall(function()
        if state.nft_sess then
          state.nft_sess.run_nft("add element bridge dns-filter-bridge " .. tostring(rule_id) .. "_auth_mac { " .. tostring(mac) .. " timeout " .. tostring(state.auth_cfg.idle_timeout) .. "s }", {
            quiet = true
          })
          log_info({
            action = "server_auth_set_add_mac",
            rule_id = rule_id,
            mac = mac
          })
          if peer_ip and peer_ip ~= "unknown" then
            if peer_ip:find(":") then
              state.nft_sess.run_nft("add element bridge dns-filter-bridge " .. tostring(rule_id) .. "_auth_ip6 { " .. tostring(peer_ip) .. " timeout " .. tostring(state.auth_cfg.idle_timeout) .. "s }", {
                quiet = true
              })
              return log_info({
                action = "server_auth_set_add_ip6",
                rule_id = rule_id,
                ip = peer_ip
              })
            else
              state.nft_sess.run_nft("add element bridge dns-filter-bridge " .. tostring(rule_id) .. "_auth_ip4 { " .. tostring(peer_ip) .. " timeout " .. tostring(state.auth_cfg.idle_timeout) .. "s }", {
                quiet = true
              })
              return log_info({
                action = "server_auth_set_add_ip4",
                rule_id = rule_id,
                ip = peer_ip
              })
            end
          end
        end
      end)
      if not (ok) then
        log_warn({
          action = "server_auth_set_add_failed",
          rule_id = rule_id,
          mac = mac,
          ip = peer_ip,
          err = tostring(err)
        })
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  local tok = token.generate("user", user, mac, now + idle_timeout, state.token_key)
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8",
    ["Set-Cookie"] = make_session_cookie(tok)
  }, success_page(state.auth_cfg, now)
end
local handle_ping
handle_ping = function(req, peer_ip, peer_mac, state)
  log_info({
    action = "server_ping_received",
    peer_ip = peer_ip,
    peer_mac = peer_mac
  })
  local cookie_val = token.get_cookie(req.headers.cookie or "", COOKIE_NAME)
  local p, tok_err = token.verify(cookie_val, state.token_key)
  if not (p) then
    log_info({
      action = "server_ping_token_invalid",
      peer_ip = peer_ip,
      err = tok_err
    })
    return 401, { }, ""
  end
  local user = p.user
  local mac = p.mac
  local idle_timeout = state.auth_cfg.idle_timeout or 120
  local now = os.time()
  local new_expires = now + idle_timeout
  local sessions = load_sessions(state.sessions_file)
  purge_expired(sessions)
  add_session(sessions, mac, peer_ip, user, new_expires)
  write_sessions(sessions, state.sessions_file)
  refresh_nft(state.nft_sess, peer_ip, mac, idle_timeout, user)
  local new_tok = token.generate("user", user, mac, new_expires, state.token_key)
  log_info({
    action = "server_ping_success",
    peer_mac = mac
  })
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
    local filter_cfg = config.filter or { }
    local rules = filter_cfg.rules or { }
    for idx, rule in ipairs(rules) do
      local _continue_0 = false
      repeat
        if not (rule_requires_auth(rule)) then
          _continue_0 = true
          break
        end
        if not (user_qualifies_for_rule(user, rule)) then
          _continue_0 = true
          break
        end
        rule_id = generate_rule_id(rule, idx)
        local ok, err = pcall(function()
          state.nft_sess.run_nft("delete element bridge dns-filter-bridge " .. tostring(rule_id) .. "_auth_mac { " .. tostring(mac) .. " }", {
            quiet = true
          })
          if peer_ip and peer_ip ~= "unknown" then
            if peer_ip:find(":") then
              return state.nft_sess.run_nft("delete element bridge dns-filter-bridge " .. tostring(rule_id) .. "_auth_ip6 { " .. tostring(peer_ip) .. " }", {
                quiet = true
              })
            else
              return state.nft_sess.run_nft("delete element bridge dns-filter-bridge " .. tostring(rule_id) .. "_auth_ip4 { " .. tostring(peer_ip) .. " }", {
                quiet = true
              })
            end
          end
        end)
        if not (ok) then
          log_warn({
            action = "server_auth_set_delete_failed",
            rule_id = rule_id,
            mac = mac,
            ip = peer_ip,
            err = tostring(err)
          })
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
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
    log_warn({
      action = "server_reload_signal_failed",
      parent_pid = tonumber(ffi.C.getppid())
    })
  end
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, register_success_page(req)
end
local css_content = [[  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.5;
    color: #333;
    background-color: #f5f5f5;
    padding: 1rem;
    max-width: 1200px;
    margin: 0 auto;
  }

  form {
    background: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin: 1rem 0;
  }

  label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 500;
  }

  input[type="text"],
  input[type="password"] {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 1rem;
    margin-bottom: 1rem;
  }

  button {
    background-color: #007bff;
    color: white;
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 0.2s;
  }

  button:hover {
    background-color: #0056b3;
  }

  p {
    margin: 1rem 0;
  }

  a {
    color: #007bff;
    text-decoration: none;
  }

  a:hover {
    text-decoration: underline;
  }

  @media (max-width: 768px) {
    body {
      padding: 0.5rem;
    }

    form {
      padding: 1rem;
    }
  }

  @media (max-width: 480px) {
    body {
      padding: 0.25rem;
    }

    form {
      padding: 0.75rem;
    }
  }
  ]]
local handle_request
handle_request = function(req, peer_ip, peer_mac, state)
  log_info({
    action = "server_request_received",
    path = req.path,
    method = req.method,
    peer_ip = peer_ip,
    peer_mac = peer_mac
  })
  if req.path == "/" and req.method == "GET" then
    return 200, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, login_page()
  elseif req.path == "/css" and req.method == "GET" then
    return 200, {
      ["Content-Type"] = "text/css"
    }, css_content
  elseif req.path == "/login" and req.method == "POST" then
    log_info({
      action = "server_routing_to_handle_login",
      path = req.path,
      method = req.method
    })
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
local handle_client
handle_client = function(args)
  local client = args.client
  local state = args.state
  local peer_ip = args.peer_ip or "unknown"
  local ok, err = pcall(function()
    log_debug({
      action = "server_handle_client_start",
      peer = peer_ip,
      fd = client.fd
    })
    local local_ip = client:getsockname()
    if not (local_ip) then
      local errno = tonumber(ffi.C.__errno_location()[0])
      log_warn({
        action = "server_getsockname_failed",
        peer = peer_ip,
        errno = errno
      })
      local_ip = "custos"
    end
    log_debug({
      action = "server_local_ip_detected",
      local_ip = local_ip
    })
    local tls_ctx = nil
    if state.static_cert_paths then
      log_debug({
        action = "server_loading_static_cert_child",
        cert = state.static_cert_paths.cert,
        key = state.static_cert_paths.key
      })
      local ctx
      ctx, err = load_static(state.static_cert_paths.key, state.static_cert_paths.cert)
      if ctx then
        tls_ctx = ctx
        log_debug({
          action = "server_using_static_cert"
        })
      else
        log_error({
          action = "server_static_cert_load_child_failed",
          err = err
        })
        error("Cannot load static certificate in child: " .. tostring(err))
      end
    else
      local tls_ctx_ok, tls_ctx_err = pcall(function()
        tls_ctx = load_or_generate_sni(local_ip, state.cert_cache)
      end)
      if not (tls_ctx_ok) then
        log_error({
          action = "server_cert_generation_failed",
          local_ip = local_ip,
          err = tls_ctx_err
        })
        error("Cannot generate certificate: " .. tostring(tls_ctx_err))
      end
    end
    if not (tls_ctx) then
      log_error({
        action = "server_cert_null",
        local_ip = local_ip
      })
      error("Certificate context is nil")
    end
    log_debug({
      action = "server_cert_loaded",
      local_ip = local_ip
    })
    log_debug({
      action = "server_set_blocking_mode"
    })
    client:settimeout(nil)
    log_debug({
      action = "server_blocking_mode_set"
    })
    log_debug({
      action = "server_ssl_wrap_start"
    })
    local tls_client, tls_err = ssl.wrap(client, tls_ctx)
    log_debug({
      action = "server_ssl_wrap_done"
    })
    if not (tls_client) then
      log_warn({
        action = "server_tls_wrap_failed",
        peer = peer_ip,
        err = tls_err
      })
      client:close()
      return 
    end
    log_debug({
      action = "server_dohandshake_start"
    })
    local handshake_complete = false
    local handshake_attempts = 0
    while not handshake_complete and handshake_attempts < 50 do
      handshake_attempts = handshake_attempts + 1
      log_debug({
        action = "server_handshake_attempt",
        attempt = handshake_attempts
      })
      local ok_hs, hs_err = tls_client:dohandshake()
      log_debug({
        action = "server_dohandshake_returned",
        ok = ok_hs
      })
      if ok_hs then
        log_debug({
          action = "server_handshake_complete"
        })
        handshake_complete = true
      end
    end
    if not (handshake_complete) then
      if hs_err == "peer_closed" then
        log_warn({
          action = "server_tls_handshake_peer_closed",
          peer = peer_ip,
          attempts = handshake_attempts
        })
      else
        log_warn({
          action = "server_tls_handshake_failed",
          peer = peer_ip,
          attempts = handshake_attempts,
          err = hs_err or "max attempts reached"
        })
      end
      tls_client:close()
      return 
    end
    log_debug({
      action = "server_set_http_timeout"
    })
    local peer_mac = get_mac(peer_ip)
    local req, req_err = read_request(tls_client)
    if not (req) then
      log_warn({
        action = "server_request_read_failed",
        peer = peer_ip,
        err = req_err
      })
      tls_client:close()
      return 
    end
    local status, headers, body = handle_request(req, peer_ip, peer_mac, state)
    send_response(tls_client, status, headers, body)
    return tls_client:close()
  end)
  if not (ok) then
    log_error({
      action = "server_client_failed",
      peer = peer_ip,
      err = tostring(err)
    })
    return pcall(function()
      return client:close()
    end)
  end
end
local reload_secrets_if_needed
reload_secrets_if_needed = function(state)
  if not (state.reload_fn) then
    return 
  end
  local new_secrets = state.reload_fn()
  if new_secrets then
    state.secrets = new_secrets
  end
end
local make_server4
make_server4 = function(port)
  local srv = socket.tcp()
  srv:setoption("reuseaddr", true)
  local ok, err = srv:bind("0.0.0.0", port)
  if not (ok) then
    srv:close()
    return nil, err
  end
  srv:listen(32)
  srv:settimeout(1)
  return srv
end
local make_server6
make_server6 = function(port)
  local ok6, srv6 = pcall(socket.tcp6)
  if not (ok6 and srv6) then
    return nil
  end
  srv6:setoption("reuseaddr", true)
  srv6:setoption("ipv6-v6only", true)
  local ok62, _ = pcall(srv6.bind, srv6, "::", port)
  if not (ok62) then
    srv6:close()
    return nil
  end
  srv6:listen(32)
  srv6:settimeout(1)
  return srv6
end
local run
run = function(secrets, auth_cfg, reload_fn, nft_sess, secrets_path)
  local port = auth_cfg.port or 33443
  local sessions_file = auth_cfg.sessions_file or config.auth.sessions_file
  log_debug({
    action = "server_startup",
    port = port
  })
  log_debug({
    action = "server_auth_cfg_received",
    cert = auth_cfg.cert,
    key = auth_cfg.key
  })
  log_debug({
    action = "server_cert_cache_init"
  })
  local cert_cache_module = require("auth.cert_cache")
  local cert_cache = cert_cache_module.create_cache(500, 7776000)
  local static_tls_ctx = nil
  if auth_cfg.cert and auth_cfg.key then
    log_info({
      action = "server_loading_static_cert",
      cert = auth_cfg.cert,
      key = auth_cfg.key
    })
    local ok, ctx = load_static(auth_cfg.key, auth_cfg.cert)
    if ok then
      static_tls_ctx = ctx
      log_info({
        action = "server_static_cert_loaded",
        cert = auth_cfg.cert,
        key = auth_cfg.key
      })
    else
      log_warn({
        action = "server_static_cert_failed",
        cert = auth_cfg.cert,
        key = auth_cfg.key,
        err = ctx
      })
    end
  else
    log_debug({
      action = "server_no_static_cert_configured"
    })
  end
  local token_key = token.load_key(auth_cfg.session_key or "/etc/custos/session.key")
  log_info({
    action = "server_session_key_loaded"
  })
  local listen4, err4 = make_server4(port)
  if not (listen4) then
    error("Impossible de démarrer le serveur IPv4 sur port " .. tostring(port) .. " : " .. tostring(err4))
  end
  local listen6 = make_server6(port)
  local all_servers = {
    listen4
  }
  if listen6 then
    all_servers[#all_servers + 1] = listen6
  end
  local state = {
    secrets = secrets or { },
    auth_cfg = auth_cfg,
    reload_fn = reload_fn,
    nft_sess = nft_sess,
    secrets_path = secrets_path,
    sessions_file = sessions_file,
    token_key = token_key,
    config_path = auth_cfg.config_path or "/etc/custos/config.moon",
    started_at = os.time(),
    static_cert_paths = (function()
      if auth_cfg.cert and auth_cfg.key then
        return {
          cert = auth_cfg.cert,
          key = auth_cfg.key
        }
      else
        return nil
      end
    end)(),
    cert_cache = cert_cache
  }
  log_info({
    action = "server_listening",
    port = port,
    ipv4 = "0.0.0.0",
    ipv6 = listen6 and "::" or nil,
    sessions_file = sessions_file,
    cert_cache = (function()
      if auth_cfg.cert and auth_cfg.key then
        return "static cert + dynamic SNI cache"
      else
        return "dynamic SNI cache (500 slots, 90d TTL)"
      end
    end)()
  })
  while true do
    reload_secrets_if_needed(state)
    while true do
      local dead_pid = reap_one()
      if not (dead_pid and dead_pid > 0) then
        break
      end
    end
    local readable, _ = socket.select(all_servers, nil, 0.1)
    if readable then
      for _index_0 = 1, #readable do
        local srv = readable[_index_0]
        log_debug({
          action = "server_socket_select_readable"
        })
        local client = srv:accept()
        log_debug({
          action = "server_accept_returned"
        })
        if client then
          log_debug({
            action = "server_got_client"
          })
          local peer_ip = client:getpeername() or "unknown"
          log_debug({
            action = "server_getpeername_result",
            peer = peer_ip
          })
          log_debug({
            action = "server_fork_child_start",
            peer = peer_ip,
            fd = client.fd
          })
          local pid = fork_child("AUTH-conn", handle_client, {
            client = client,
            peer_ip = peer_ip,
            state = state
          }, {
            log_start = false
          })
          log_debug({
            action = "server_fork_child_done",
            pid = pid
          })
          log_info({
            action = "server_conn_started",
            pid = pid,
            peer = peer_ip
          })
          client:close()
        end
      end
    end
  end
end
return {
  run = run
}
