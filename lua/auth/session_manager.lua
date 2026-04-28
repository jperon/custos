local socket = require("socket")
local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local nft_sess = require("auth.nft_sessions")
local sessions = { }
local parse_ipc_message
parse_ipc_message = function(data)
  local type = data:byte(1)
  local ip = data:sub(2, 17)
  local mac = data:sub(18, 23)
  local body_len = data:byte(24) * 256 + data:byte(25)
  local body
  if body_len > 0 then
    body = data:sub(26, 25 + body_len)
  else
    body = ""
  end
  return type, ip, mac, body
end
local serialize_headers
serialize_headers = function(headers)
  local result = ""
  for name, value in pairs(headers) do
    result = result .. string.char(#name) .. name .. string.char(#value) .. value
  end
  return result
end
local build_ipc_response
build_ipc_response = function(status, headers, body)
  local headers_str = serialize_headers(headers)
  local headers_len = #headers_str
  local body_len = #body
  local header_part = string.pack(">H2H2I4", status, headers_len, body_len)
  return header_part .. headers_str .. body
end
local add_session
add_session = function(mac, ip, user, session_ttl, idle_timeout)
  local now = os.time()
  sessions[mac] = {
    user = user,
    mac = mac,
    ips = {
      ipv4 = ip:sub(1, 4),
      ipv6 = ip:sub(5, 16)
    },
    heartbeat = now + idle_timeout,
    expires = now + session_ttl
  }
end
local purge_expired
purge_expired = function()
  local now = os.time()
  local expired = { }
  for mac, s in pairs(sessions) do
    if s.expires < now then
      expired[mac] = s
    end
  end
  for mac in pairs(expired) do
    sessions[mac] = nil
  end
  return expired
end
local handle_login
handle_login = function(ip, mac, body)
  local user, pass = body:match("user=([^&]+)&password=([^&]+)")
  if not (user and pass) then
    return 400, { }, "Missing credentials"
  end
  local secrets = load_secrets()
  local ok, err = verify_password(user, pass)
  if not (ok) then
    return 401, { }, "Invalid credentials"
  end
  purge_expired()
  if mac ~= "\xFF\xFF\xFF\xFF\xFF\xFF" then
    mac = mac
  else
    mac = nil
  end
  add_session(mac, ip, user, auth_cfg.session_ttl, auth_cfg.idle_timeout)
  if nft_sess then
    nft_sess:add_authenticated(ip, auth_cfg.idle_timeout)
    if mac then
      nft_sess:add_authenticated_mac(mac, auth_cfg.idle_timeout)
    end
  end
  local success_page = [[    <!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"/>
    <title>CustosVirginum — Authentification</title>
    <script>
      var iv = 5 * 1000;
      function ping(){
        fetch('/ping',{method:'GET',credentials:'omit'})
          .then(function(r){ if(r.status===401) location.href='/'; })
          .catch(function(){});
      }
      setInterval(ping, iv);
      ping();
    </script>
    </head><body>
    <p>Connexion réussie. Votre accès réseau est actif.</p>
    </body></html>
  ]]
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, success_page
end
local handle_ping
handle_ping = function(ip, mac)
  for mac_key, s in pairs(sessions) do
    if s.ips and (s.ips.ipv4 == ip:sub(1, 4) or s.ips.ipv6 == ip:sub(5, 16)) then
      local now = os.time()
      if now <= s.expires and (not s.heartbeat or now <= s.heartbeat) then
        if auth_cfg.idle_timeout and auth_cfg.idle_timeout > 0 then
          s.heartbeat = now + auth_cfg.idle_timeout
        end
        if nft_sess then
          nft_sess:add_authenticated(ip, auth_cfg.idle_timeout)
          if s.mac then
            nft_sess:add_authenticated_mac(s.mac, auth_cfg.idle_timeout)
          end
        end
        return 204, { }, ""
      end
    end
  end
  return 401, { }, ""
end
local handle_logout
handle_logout = function(ip, mac)
  for mac_key, s in pairs(sessions) do
    if s.ips and (s.ips.ipv4 == ip:sub(1, 4) or s.ips.ipv6 == ip:sub(5, 16)) then
      if nft_sess then
        nft_sess:del_authenticated(ip)
        if s.mac then
          nft_sess:del_authenticated_mac(s.mac)
        end
      end
      sessions[mac_key] = nil
      return 302, {
        ["Location"] = "/"
      }, ""
    end
  end
  return 404, { }, ""
end
local handle_register
handle_register = function(ip, mac, body)
  local user, pass = body:match("user=([^&]+)&password=([^&]+)")
  if not (user and pass) then
    return 400, { }, "Missing credentials"
  end
  local secrets = load_secrets()
  if secrets[user] then
    return 409, { }, "User already exists"
  end
  local ok, err = register_user(user, pass)
  if not (ok) then
    return 500, { }, "Registration failed"
  end
  return 200, {
    ["Content-Type"] = "text/html; charset=UTF-8"
  }, [[    <html><body>
      <p>Compte créé. Vous pouvez maintenant vous connecter.</p>
      <a href="/">Se connecter</a>
    </body></html>
  ]]
end
local main
main = function()
  while true do
    local msg = io.stdin:read(25)
    if not (msg) then
      break
    end
    local type, ip, mac, body = parse_ipc_message(msg)
    local status, headers, response
    if type == 0x01 then
      status, headers, response = handle_login(ip, mac, body)
    elseif type == 0x02 then
      status, headers, response = handle_ping(ip, mac)
    elseif type == 0x03 then
      status, headers, response = handle_logout(ip, mac)
    elseif type == 0x04 then
      status, headers, response = handle_register(ip, mac, body)
    else
      status, headers, response = 400, { }, "Invalid request"
    end
    local response_ipc = build_ipc_response(status, headers, response)
    io.stdout:write(response_ipc)
  end
end
return main()
