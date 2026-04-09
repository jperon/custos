local socket = require("socket")
local ssl = require("ssl")
local verify_password, load_secrets
do
  local _obj_0 = require("auth.credentials")
  verify_password, load_secrets = _obj_0.verify_password, _obj_0.load_secrets
end
local add_session, purge_expired, write_sessions
do
  local _obj_0 = require("auth.sessions")
  add_session, purge_expired, write_sessions = _obj_0.add_session, _obj_0.purge_expired, _obj_0.write_sessions
end
local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local LOGIN_PAGE = [[<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CustosVirginum — Authentification</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body {
      font-family: system-ui, sans-serif;
      background: #f4f4f4;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
      margin: 0;
    }
    .card {
      background: white;
      padding: 2rem;
      border-radius: 8px;
      box-shadow: 0 2px 12px rgba(0,0,0,.15);
      width: 100%;
      max-width: 380px;
    }
    h1 { font-size: 1.3rem; margin: 0 0 1.5rem; color: #222; }
    label { display: block; margin-bottom: 1rem; }
    label span { display: block; font-size: .85rem; color: #555; margin-bottom: .3rem; }
    input[type=text], input[type=password] {
      width: 100%;
      padding: .5rem .7rem;
      border: 1px solid #ccc;
      border-radius: 4px;
      font-size: 1rem;
    }
    button {
      width: 100%;
      padding: .6rem;
      background: #2563eb;
      color: white;
      border: none;
      border-radius: 4px;
      font-size: 1rem;
      cursor: pointer;
      margin-top: .5rem;
    }
    button:hover { background: #1d4ed8; }
    .msg { margin-top: 1rem; padding: .6rem; border-radius: 4px; font-size: .9rem; }
    .msg.ok  { background: #dcfce7; color: #166534; }
    .msg.err { background: #fee2e2; color: #991b1b; }
  </style>
</head>
<body>
  <div class="card">
    <h1>CustosVirginum</h1>
    <form method="post" action="/login">
      <label>
        <span>Nom d'utilisateur</span>
        <input type="text" name="user" required autofocus>
      </label>
      <label>
        <span>Mot de passe</span>
        <input type="password" name="password" required>
      </label>
      <button type="submit">Se connecter</button>
    </form>
    %MSG%
  </div>
</body>
</html>
]]
local SUCCESS_PAGE = LOGIN_PAGE:gsub("%%MSG%%", '<p class="msg ok">Connexion réussie. Votre accès réseau est actif.</p>')
local failure_page
failure_page = function(reason)
  return LOGIN_PAGE:gsub("%%MSG%%", "<p class=\"msg err\">" .. tostring(reason) .. "</p>")
end
local home_page = LOGIN_PAGE:gsub("%%MSG%%", "")
local read_request
read_request = function(sock)
  local line, err = sock:receive("*l")
  if not (line) then
    return nil, err
  end
  local method, path = line:match("^(%u+)%s+([^%s]+)")
  if not (method) then
    return nil, "bad request line: " .. tostring(line)
  end
  local headers = { }
  local content_length = 0
  while true do
    local hline, herr = sock:receive("*l")
    if not hline or hline == "" then
      break
    end
    if not hline then
      return nil, herr
    end
    local name, val = hline:match("^([^:]+):%s*(.*)")
    if name then
      headers[name:lower()] = val
      if name:lower() == "content-length" then
        content_length = tonumber(val) or 0
      end
    end
  end
  local body = ""
  if content_length > 0 then
    body = sock:receive(content_length)
  end
  return method, path, headers, body
end
local decode_form
decode_form = function(s)
  local t = { }
  for pair in (s or ""):gmatch("[^&]+") do
    local k, v = pair:match("^([^=]+)=?(.*)$")
    if k then
      local decode
      decode = function(x)
        return x:gsub("+", " "):gsub("%%(%x%x)", function(h)
          return string.char(tonumber(h, 16))
        end)
      end
      t[decode(k)] = decode(v)
    end
  end
  return t
end
local http_response
http_response = function(sock, status, body, extra_headers)
  extra_headers = extra_headers or ""
  local resp = table.concat({
    "HTTP/1.1 " .. tostring(status) .. "\r\n",
    "Content-Type: text/html; charset=UTF-8\r\n",
    "Content-Length: " .. tostring(#body) .. "\r\n",
    "Connection: close\r\n",
    "X-Frame-Options: DENY\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    extra_headers,
    "\r\n",
    body
  })
  return sock:send(resp)
end
local http_redirect
http_redirect = function(sock, location)
  local resp = "HTTP/1.1 303 See Other\r\nLocation: " .. tostring(location) .. "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  return sock:send(resp)
end
local handle_connection
handle_connection = function(raw_sock, tls_ctx, secrets, sessions, auth_cfg, peer_ip)
  raw_sock:settimeout(10)
  local tls_sock, err = ssl.wrap(raw_sock, tls_ctx)
  if not (tls_sock) then
    log_warn({
      action = "auth_tls_wrap_failed",
      ip = peer_ip,
      err = err
    })
    return 
  end
  local ok, err2 = tls_sock:dohandshake()
  if not (ok) then
    log_warn({
      action = "auth_tls_handshake_failed",
      ip = peer_ip,
      err = err2
    })
    tls_sock:close()
    return 
  end
  local method, path, headers, body = read_request(tls_sock)
  if not (method) then
    tls_sock:close()
    return 
  end
  if method == "GET" and (path == "/" or path == "/login") then
    local s = sessions[peer_ip]
    if s and os.time() <= s.expires then
      http_response(tls_sock, "200 OK", SUCCESS_PAGE)
      log_info({
        action = "auth_already_logged",
        ip = peer_ip,
        user = s.user
      })
    else
      http_response(tls_sock, "200 OK", home_page)
    end
  elseif method == "GET" and path == "/logout" then
    sessions[peer_ip] = nil
    local ok2, err3 = write_sessions(sessions, auth_cfg.sessions_file)
    if not (ok2) then
      log_warn({
        action = "auth_write_failed",
        err = err3
      })
    end
    http_redirect(tls_sock, "/")
    log_info({
      action = "auth_logout",
      ip = peer_ip
    })
  elseif method == "POST" and path == "/login" then
    local form = decode_form(body)
    local user = form.user or ""
    local pass = form.password or ""
    local stored = secrets[user]
    if stored and pass ~= "" and verify_password(pass, stored) then
      purge_expired(sessions)
      add_session(sessions, peer_ip, user, auth_cfg.session_ttl)
      local ok2, err3 = write_sessions(sessions, auth_cfg.sessions_file)
      if not (ok2) then
        log_warn({
          action = "auth_write_failed",
          err = err3
        })
      end
      http_response(tls_sock, "200 OK", SUCCESS_PAGE)
      log_info({
        action = "auth_login_ok",
        ip = peer_ip,
        user = user
      })
    else
      http_response(tls_sock, "401 Unauthorized", failure_page("Nom d'utilisateur ou mot de passe incorrect."))
      log_warn({
        action = "auth_login_failed",
        ip = peer_ip,
        user = user
      })
    end
  else
    http_response(tls_sock, "404 Not Found", "<h1>404</h1>")
  end
  return tls_sock:close()
end
local make_server4
make_server4 = function(host, port)
  local srv = socket.tcp()
  srv:setoption("reuseaddr", true)
  local ok4, err = srv:bind(host, port)
  if not (ok4) then
    srv:close()
    return nil, err
  end
  srv:listen(8)
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
  local ok62, _err = srv6:bind("::", port)
  if not (ok62) then
    srv6:close()
    return nil
  end
  srv6:listen(8)
  srv6:settimeout(1)
  return srv6
end
local run
run = function(tls_ctx, secrets, auth_cfg, reload_fn)
  local port = auth_cfg.port
  local host = auth_cfg.host
  local listen4, err4 = make_server4("0.0.0.0", port)
  if not (listen4) then
    error("Impossible de démarrer le serveur IPv4 sur port " .. tostring(port) .. " : " .. tostring(err4))
  end
  local listen6 = make_server6(port)
  if listen6 then
    log_info({
      action = "auth_listening",
      ipv4 = "0.0.0.0",
      ipv6 = "::",
      port = port
    })
  else
    log_info({
      action = "auth_listening",
      ipv4 = "0.0.0.0",
      port = port
    })
  end
  local sessions = { }
  local servers = listen6 and {
    listen4,
    listen6
  } or {
    listen4
  }
  while true do
    if reload_fn then
      local new_secrets = reload_fn()
      if new_secrets then
        secrets = new_secrets
      end
    end
    local readable = socket.select(servers, nil, 1)
    local _list_0 = (readable or { })
    for _index_0 = 1, #_list_0 do
      local srv = _list_0[_index_0]
      local client, peer_ip = srv:accept()
      if client then
        handle_connection(client, tls_ctx, secrets, sessions, auth_cfg, peer_ip)
      end
    end
  end
end
return {
  run = run,
  handle_connection = handle_connection,
  decode_form = decode_form,
  failure_page = failure_page,
  home_page = home_page,
  SUCCESS_PAGE = SUCCESS_PAGE
}
