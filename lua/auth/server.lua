local socket = require("socket")
local verify_password, load_secrets, register_user
do
  local _obj_0 = require("auth.credentials")
  verify_password, load_secrets, register_user = _obj_0.verify_password, _obj_0.load_secrets, _obj_0.register_user
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
local captive = require("auth.captive")
local neigh = require("neigh")
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
    .link { text-align: center; margin-top: 1rem; font-size: .9rem; }
    .link a { color: #2563eb; text-decoration: none; }
    .link a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <h1>CustosVirginum</h1>
    <div %AUTH_HIDDEN%>
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
      <div class="link"><a href="/register">Créer un compte</a></div>
    </div>
    %MSG%
  </div>
</body>
</html>
]]
local REGISTER_PAGE = [[<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CustosVirginum — Inscription</title>
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
      background: #16a34a;
      color: white;
      border: none;
      border-radius: 4px;
      font-size: 1rem;
      cursor: pointer;
      margin-top: .5rem;
    }
    button:hover { background: #15803d; }
    .msg { margin-top: 1rem; padding: .6rem; border-radius: 4px; font-size: .9rem; }
    .msg.ok  { background: #dcfce7; color: #166534; }
    .msg.err { background: #fee2e2; color: #991b1b; }
    .link { text-align: center; margin-top: 1rem; font-size: .9rem; }
    .link a { color: #2563eb; text-decoration: none; }
    .link a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Créer un compte</h1>
    <form method="post" action="/register">
      <label>
        <span>Nom d'utilisateur</span>
        <input type="text" name="user" required autofocus minlength="3" maxlength="32" pattern="[a-zA-Z0-9_.\-]+">
      </label>
      <label>
        <span>Mot de passe (8 caractères minimum)</span>
        <input type="password" name="password" required minlength="8">
      </label>
      <label>
        <span>Confirmer le mot de passe</span>
        <input type="password" name="password2" required minlength="8">
      </label>
      <button type="submit">Créer le compte</button>
    </form>
    <div class="link"><a href="/">Déjà un compte ? Se connecter</a></div>
    %MSG%
  </div>
</body>
</html>
]]
local success_page_tmp, _ = LOGIN_PAGE:gsub("%%MSG%%", '<p class="msg ok">Connexion réussie. Votre accès réseau est actif.</p>')
local SUCCESS_PAGE_RAW
SUCCESS_PAGE_RAW, _ = success_page_tmp:gsub("%%AUTH_HIDDEN%%", 'style="display:none"')
local SUCCESS_PAGE = SUCCESS_PAGE_RAW
local make_success_page
make_success_page = function(interval)
  local js = string.format([[<script>
(function(){
  var iv = %d * 1000;
  function ping(){
    fetch('/ping',{method:'GET',credentials:'omit'})
      .then(function(r){ if(r.status===401) location.href='/'; })
      .catch(function(){});
  }
  setInterval(ping, iv);
  ping();
})();
</script>]], interval)
  local res
  res, _ = LOGIN_PAGE:gsub("%%MSG%%", '<p class="msg ok">Connexion r\xc3\xa9ussie. Votre acc\xc3\xa8s r\xc3\xa9seau est actif tant que cette page reste ouverte.</p>' .. js)
  local res2
  res2, _ = res:gsub("%%AUTH_HIDDEN%%", 'style="display:none"')
  return res2
end
local failure_page
failure_page = function(reason)
  local res
  res, _ = LOGIN_PAGE:gsub("%%MSG%%", "<p class=\"msg err\">" .. tostring(reason) .. "</p>")
  local res2
  res2, _ = res:gsub("%%AUTH_HIDDEN%%", "")
  return res2
end
local register_failure_page
register_failure_page = function(reason)
  local res
  res, _ = REGISTER_PAGE:gsub("%%MSG%%", "<p class=\"msg err\">" .. tostring(reason) .. "</p>")
  return res
end
local home_page_raw
home_page_raw, _ = LOGIN_PAGE:gsub("%%MSG%%", "")
local home_page_raw2
home_page_raw2, _ = home_page_raw:gsub("%%AUTH_HIDDEN%%", "")
local home_page = home_page_raw2
local home_register_page_raw
home_register_page_raw, _ = REGISTER_PAGE:gsub("%%MSG%%", "")
local home_register_page = home_register_page_raw
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
local register_rate_exceeded
register_rate_exceeded = function(register_attempts, peer_ip, max_attempts, window_sec)
  local now = os.time()
  local entry = register_attempts[peer_ip]
  if entry then
    if now - entry.ts > window_sec then
      register_attempts[peer_ip] = {
        count = 1,
        ts = now
      }
      return false
    end
    entry.count = entry.count + 1
    if entry.count > max_attempts then
      return true
    end
  else
    register_attempts[peer_ip] = {
      count = 1,
      ts = now
    }
  end
  return false
end
local handle_connection
handle_connection = function(raw_sock, secrets, sessions, auth_cfg, peer_ip, success_pg, nft_sess, secrets_path, register_attempts, peer_mac)
  raw_sock:settimeout(10)
  local method, path, headers, body = read_request(raw_sock)
  if not (method) then
    raw_sock:close()
    return 
  end
  if method == "GET" and (path == "/" or path == "/login") then
    local s = sessions[peer_ip]
    local now = os.time()
    if s and now <= s.expires and (not s.heartbeat or now <= s.heartbeat) then
      http_response(raw_sock, "200 OK", success_pg)
      log_info({
        action = "auth_already_logged",
        ip = peer_ip,
        mac = peer_mac,
        user = s.user
      })
    else
      http_response(raw_sock, "200 OK", home_page)
    end
  elseif method == "GET" and path == "/ping" then
    local s = sessions[peer_ip]
    local now = os.time()
    if s and now <= s.expires and (not s.heartbeat or now <= s.heartbeat) then
      if auth_cfg.idle_timeout and auth_cfg.idle_timeout > 0 then
        s.heartbeat = now + auth_cfg.idle_timeout
        local ok2, err3 = write_sessions(sessions, auth_cfg.sessions_file)
        if not (ok2) then
          log_warn({
            action = "auth_write_failed",
            err = err3
          })
        end
        if nft_sess then
          nft_sess.add_authenticated(peer_ip, auth_cfg.idle_timeout)
        end
      end
      http_response(raw_sock, "204 No Content", "")
    else
      http_response(raw_sock, "401 Unauthorized", "")
    end
  elseif method == "GET" and path == "/logout" then
    sessions[peer_ip] = nil
    if nft_sess then
      nft_sess.del_authenticated(peer_ip)
    end
    local ok2, err3 = write_sessions(sessions, auth_cfg.sessions_file)
    if not (ok2) then
      log_warn({
        action = "auth_write_failed",
        err = err3
      })
    end
    http_redirect(raw_sock, "/")
    log_info({
      action = "auth_logout",
      ip = peer_ip,
      mac = peer_mac
    })
  elseif method == "GET" and path == "/register" then
    http_response(raw_sock, "200 OK", home_register_page)
  elseif method == "POST" and path == "/login" then
    local form = decode_form(body)
    local user = form.user or ""
    local pass = form.password or ""
    local stored = secrets[user]
    if stored and pass ~= "" and verify_password(pass, stored) then
      purge_expired(sessions)
      add_session(sessions, peer_ip, user, auth_cfg.session_ttl, auth_cfg.idle_timeout)
      if nft_sess then
        nft_sess.add_authenticated(peer_ip, auth_cfg.session_ttl)
      end
      local ok2, err3 = write_sessions(sessions, auth_cfg.sessions_file)
      if not (ok2) then
        log_warn({
          action = "auth_write_failed",
          err = err3
        })
      end
      http_response(raw_sock, "200 OK", success_pg)
      log_info({
        action = "auth_login_ok",
        ip = peer_ip,
        mac = peer_mac,
        user = user
      })
    else
      http_response(raw_sock, "401 Unauthorized", failure_page("Nom d'utilisateur ou mot de passe incorrect."))
      log_warn({
        action = "auth_login_failed",
        ip = peer_ip,
        mac = peer_mac,
        user = user
      })
    end
  elseif method == "POST" and path == "/register" then
    local max_attempts = auth_cfg.register_rate_limit or 3
    local window_sec = auth_cfg.register_rate_window or 300
    if register_rate_exceeded(register_attempts, peer_ip, max_attempts, window_sec) then
      http_response(raw_sock, "429 Too Many Requests", register_failure_page("Trop de tentatives d'inscription. Réessayez plus tard."))
      log_warn({
        action = "auth_register_rate_limited",
        ip = peer_ip,
        mac = peer_mac
      })
    else
      local form = decode_form(body)
      local user = form.user or ""
      local pass = form.password or ""
      local pass2 = form.password2 or ""
      if pass ~= pass2 then
        http_response(raw_sock, "400 Bad Request", register_failure_page("Les mots de passe ne correspondent pas."))
        log_warn({
          action = "auth_register_password_mismatch",
          ip = peer_ip,
          mac = peer_mac,
          user = user
        })
      else
        local new_secrets, reg_err = register_user(user, pass, secrets_path, secrets)
        if new_secrets then
          purge_expired(sessions)
          add_session(sessions, peer_ip, user, auth_cfg.session_ttl, auth_cfg.idle_timeout)
          if nft_sess then
            nft_sess.add_authenticated(peer_ip, auth_cfg.session_ttl)
          end
          local ok2, err3 = write_sessions(sessions, auth_cfg.sessions_file)
          if not (ok2) then
            log_warn({
              action = "auth_write_failed",
              err = err3
            })
          end
          secrets[user] = new_secrets[user]
          http_response(raw_sock, "200 OK", success_pg)
          log_info({
            action = "auth_register_ok",
            ip = peer_ip,
            mac = peer_mac,
            user = user
          })
        else
          local user_msg = reg_err
          local status = "400 Bad Request"
          if reg_err:match("déjà pris") then
            user_msg = "Impossible de créer ce compte. Veuillez choisir un autre nom."
            status = "409 Conflict"
          end
          http_response(raw_sock, status, register_failure_page(user_msg))
          log_warn({
            action = "auth_register_failed",
            ip = peer_ip,
            mac = peer_mac,
            user = user,
            err = reg_err
          })
        end
      end
    end
  else
    http_response(raw_sock, "404 Not Found", "<h1>404</h1>")
  end
  return raw_sock:close()
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
run = function(secrets, auth_cfg, reload_fn, nft_sess, captive_srvs, secrets_path)
  local port = auth_cfg.port or 33080
  local host = auth_cfg.host or "::"
  secrets_path = auth_cfg.secrets or "cfg/secrets"
  local hb_interval = auth_cfg.heartbeat_interval or 30
  local success_pg = make_success_page(hb_interval)
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
  local register_attempts = { }
  captive_srvs = captive_srvs or { }
  local auth_set = { }
  auth_set[listen4] = true
  if listen6 then
    auth_set[listen6] = true
  end
  local all_servers = {
    listen4
  }
  if listen6 then
    all_servers[#all_servers + 1] = listen6
  end
  for _index_0 = 1, #captive_srvs do
    local s = captive_srvs[_index_0]
    all_servers[#all_servers + 1] = s
  end
  while true do
    if reload_fn then
      local new_secrets = reload_fn()
      if new_secrets then
        secrets = new_secrets
      end
    end
    local readable = socket.select(all_servers, nil, 1)
    local _list_0 = (readable or { })
    for _index_0 = 1, #_list_0 do
      local srv = _list_0[_index_0]
      local client, _err = srv:accept()
      if client then
        local peer_ip = client:getpeername()
        peer_ip = tostring(peer_ip)
        local peer_mac = neigh.get_mac(peer_ip)
        if auth_set[srv] then
          handle_connection(client, secrets, sessions, auth_cfg, peer_ip, success_pg, nft_sess, secrets_path, register_attempts, peer_mac)
        else
          captive.handle_connection(client, port)
        end
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
