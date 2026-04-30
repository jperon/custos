local socket = require("socket")
local ssl = require("ssl")
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
local verify_password, register_user
do
  local _obj_0 = require("auth.credentials")
  verify_password, register_user = _obj_0.verify_password, _obj_0.register_user
end
local load_or_generate
load_or_generate = require("auth.cert").load_or_generate
local log_info, log_warn, log_error
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error
end
local AUTH_SESSIONS_FILE
AUTH_SESSIONS_FILE = require("config").AUTH_SESSIONS_FILE
local get_mac
get_mac = require("mac_learner_ipc").get_mac
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
local read_request
read_request = function(client)
  local request_line, err = client:receive("*l")
  if not (request_line) then
    return nil, err
  end
  local method, path = request_line:match("^(%w+)%s+([^%s]+)%s+HTTP")
  if not (method and path) then
    return nil, "bad_request_line"
  end
  local headers = { }
  local content_length = 0
  while true do
    local line, line_err = client:receive("*l")
    if not (line) then
      return nil, line_err
    end
    if line == "" then
      break
    end
    local name, value = line:match("^([^:]+):%s*(.*)$")
    if name then
      local lname = name:lower()
      headers[lname] = value
      if lname == "content-length" then
        content_length = tonumber(value) or 0
      end
    end
  end
  local body = ""
  if content_length > 0 then
    body = client:receive(content_length)
    body = body or ""
  end
  return {
    method = method,
    path = path,
    headers = headers,
    body = body
  }
end
local send_response
send_response = function(client, status, headers, body)
  body = body or ""
  local reason
  local _exp_0 = status
  if 200 == _exp_0 then
    reason = "OK"
  elseif 204 == _exp_0 then
    reason = "No Content"
  elseif 302 == _exp_0 then
    reason = "Found"
  elseif 400 == _exp_0 then
    reason = "Bad Request"
  elseif 401 == _exp_0 then
    reason = "Unauthorized"
  elseif 404 == _exp_0 then
    reason = "Not Found"
  elseif 409 == _exp_0 then
    reason = "Conflict"
  else
    reason = "Internal Server Error"
  end
  headers = headers or { }
  if not (headers["Content-Length"]) then
    headers["Content-Length"] = tostring(#body)
  end
  if not (headers["Connection"]) then
    headers["Connection"] = "close"
  end
  client:send("HTTP/1.1 " .. tostring(status) .. " " .. tostring(reason) .. "\r\n")
  for name, value in pairs(headers) do
    client:send(tostring(name) .. ": " .. tostring(value) .. "\r\n")
  end
  client:send("\r\n")
  if #body > 0 then
    return client:send(body)
  end
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
  local session_start = tonumber(created_at) or 0
  return page({
    H.p("Connexion réussie. Votre accès est actif tant que cette fenêtre est ouverte."),
    H.p({
      id = "session-timer"
    }, "Session ouverte depuis : --"),
    H.p(H.a({
      href = "/logout"
    }, "Déconnexion")),
    H.script("\n      var iv = " .. tostring(interval) .. " * 1000;\n      var sessionStart = " .. tostring(session_start) .. ";\n      function ping(){\n        fetch('/ping',{method:'GET',credentials:'omit'})\n          .then(function(r){\n            if(r.status===401){\n              if(document.visibilityState!=='visible')\n                alert('Connexion perdue, veuillez vous authentifier de nouveau.');\n              location.href='/';\n            }\n          })\n          .catch(function(){});\n      }\n      function updateTimer(){\n        var now = Math.floor(Date.now() / 1000);\n        var elapsed = now - sessionStart;\n        if (elapsed < 0) elapsed = 0;\n        var h = Math.floor(elapsed / 3600);\n        var m = Math.floor((elapsed % 3600) / 60);\n        var txt;\n        if (h > 0) {\n          txt = h + 'h ' + (m < 10 ? '0' : '') + m + 'min';\n        } else {\n          txt = m + ' min';\n        }\n        var el = document.getElementById('session-timer');\n        if (el) el.textContent = 'Session ouverte depuis : ' + txt;\n      }\n      setInterval(ping, iv);\n      setInterval(updateTimer, 10000);\n      ping();\n      updateTimer();\n      // Envoyer un ping immédiat au retour en foreground (anti-throttling navigateur).\n      document.addEventListener('visibilitychange', function(){\n        if (document.visibilityState === 'visible') ping();\n      });\n      // Déconnexion explicite à la fermeture du navigateur / de l'onglet.\n      // sendBeacon est envoyé de manière garantie même pendant le déchargement.\n      // pagehide est plus fiable que beforeunload sur mobile (iOS Safari).\n      // On ne déconnecte pas si la page est mise en BFCache (event.persisted).\n      function logout(){\n        if (navigator.sendBeacon) {\n          navigator.sendBeacon('/logout');\n        } else {\n          fetch('/logout', {method:'GET', keepalive:true, credentials:'omit'});\n        }\n      }\n      window.addEventListener('pagehide', function(e){\n        if (!e.persisted) logout();\n      });\n    ")
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
local refresh_nft
refresh_nft = function(nft_sess, ip, mac, ttl)
  if not (nft_sess) then
    return 
  end
  if ip and ip ~= "unknown" then
    nft_sess.add_authenticated(ip, ttl)
  end
  if mac and mac ~= "unknown" then
    return nft_sess.add_authenticated_mac(mac, ttl)
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
  if not (stored and verify_password(pass, stored)) then
    return 401, { }, "Invalid credentials"
  end
  local sessions = load_sessions(state.sessions_file)
  purge_expired(sessions)
  local mac = peer_mac
  if not (mac and mac ~= "unknown") then
    log_warn({
      action = "auth_login_mac_missing",
      ip = peer_ip,
      mac = mac
    })
    return 401, { }, "Unable to identify client MAC (IP: " .. tostring(peer_ip) .. ")"
  end
  log_info({
    action = "auth_login_success",
    user = user,
    mac = mac,
    ip = peer_ip
  })
  local ok, err = pcall(function()
    return add_session(sessions, mac, peer_ip, user, state.auth_cfg.session_ttl, state.auth_cfg.idle_timeout)
  end)
  if not (ok) then
    log_warn({
      action = "auth_session_add_failed",
      err = tostring(err)
    })
    return 500, { }, "Session creation failed"
  end
  ok, err = write_sessions(sessions, state.sessions_file)
  if not (ok) then
    log_warn({
      action = "auth_sessions_write_failed",
      err = err
    })
    return 500, { }, "Session persistence failed"
  end
  if state.nft_sess then
    ok, err = pcall(function()
      return refresh_nft(state.nft_sess, peer_ip, mac, state.auth_cfg.idle_timeout)
    end)
    if not (ok) then
      log_warn({
        action = "auth_nft_refresh_failed",
        err = tostring(err)
      })
    end
  else
    log_warn({
      action = "auth_nft_sess_missing"
    })
  end
  local session = sessions[mac:lower()]
  local created_at = session and session.created_at or os.time()
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, success_page(state.auth_cfg, created_at)
end
local handle_ping
handle_ping = function(req, peer_ip, peer_mac, state)
  local sessions = load_sessions(state.sessions_file)
  purge_expired(sessions)
  local s = session_for_mac(peer_mac, peer_ip, state.sessions_file, sessions)
  if not (s) then
    return 401, { }, ""
  end
  local mac = s.mac or peer_mac
  local now = os.time()
  if (s.expires and now > s.expires) or (s.heartbeat and now > s.heartbeat) then
    sessions[mac] = nil
    write_sessions(sessions, state.sessions_file)
    return 401, { }, ""
  end
  if state.auth_cfg.idle_timeout and state.auth_cfg.idle_timeout > 0 then
    s.heartbeat = now + state.auth_cfg.idle_timeout
    write_sessions(sessions, state.sessions_file)
  end
  refresh_nft(state.nft_sess, peer_ip, mac, state.auth_cfg.idle_timeout)
  return 204, { }, ""
end
local handle_logout
handle_logout = function(req, peer_ip, peer_mac, state)
  local sessions = load_sessions(state.sessions_file)
  local s = session_for_mac(peer_mac, peer_ip, state.sessions_file, sessions)
  if not (s) then
    return 404, { }, ""
  end
  local mac = s.mac or peer_mac
  if state.nft_sess then
    state.nft_sess.del_authenticated(peer_ip)
    if s.mac then
      state.nft_sess.del_authenticated_mac(s.mac)
    end
  end
  sessions[mac] = nil
  write_sessions(sessions, state.sessions_file)
  return 302, {
    ["Location"] = "/"
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
  if req.path == "/" and req.method == "GET" then
    return 200, {
      ["Content-Type"] = "text/html; charset=UTF-8"
    }, login_page()
  elseif req.path == "/css" and req.method == "GET" then
    return 200, {
      ["Content-Type"] = "text/css"
    }, css_content
  elseif req.path == "/login" and req.method == "POST" then
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
    client:settimeout(10)
    local tls_client, tls_err = ssl.wrap(client, state.tls_ctx)
    if not (tls_client) then
      log_warn({
        action = "auth_tls_wrap_failed",
        err = tls_err
      })
      client:close()
      return 
    end
    local ok_hs, hs_err = tls_client:dohandshake()
    if not (ok_hs) then
      log_warn({
        action = "auth_tls_handshake_failed",
        err = hs_err
      })
      tls_client:close()
      return 
    end
    local peer_mac = get_mac(peer_ip)
    local req, req_err = read_request(tls_client)
    if not (req) then
      log_warn({
        action = "auth_request_read_failed",
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
      action = "auth_client_failed",
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
  local sessions_file = auth_cfg.sessions_file or AUTH_SESSIONS_FILE
  local cert_path = auth_cfg.cert or "tmp/auth.crt"
  local key_path = auth_cfg.key or "tmp/auth.key"
  local tls_ctx = load_or_generate(key_path, cert_path)
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
    tls_ctx = tls_ctx
  }
  log_info({
    action = "auth_listening",
    port = port,
    ipv4 = "0.0.0.0",
    ipv6 = listen6 and "::" or nil,
    sessions_file = sessions_file
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
        local client = srv:accept()
        if client then
          local peer_ip = client:getpeername() or "unknown"
          local pid = fork_child("AUTH-conn", handle_client, {
            client = client,
            peer_ip = peer_ip,
            state = state
          }, {
            log_start = false
          })
          log_info({
            action = "auth_conn_started",
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
