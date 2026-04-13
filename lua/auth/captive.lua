local socket = require("socket")
local neigh = require("neigh")
local log_info
log_info = require("log").log_info
local DETECTION_PATHS = {
  "/generate_204",
  "/hotspot-detect.html",
  "/library/test/success.html",
  "/connecttest.txt",
  "/ncsi.txt",
  "/success.txt",
  "/canonical.html"
}
local is_detection_path
is_detection_path = function(path)
  local clean = path:match("^([^?#]+)") or path
  for _index_0 = 1, #DETECTION_PATHS do
    local p = DETECTION_PATHS[_index_0]
    if clean == p then
      return true
    end
  end
  return false
end
local detect_local_ip
detect_local_ip = function()
  local u = socket.udp()
  pcall(function()
    return u:connect("8.8.8.8", 80)
  end)
  local ip, _ = u:getsockname()
  u:close()
  return (ip and ip ~= "" and ip ~= "0.0.0.0") and ip or "127.0.0.1"
end
local handle_connection
handle_connection = function(client, auth_port)
  client:settimeout(5)
  local line, _ = client:receive("*l")
  if not (line) then
    client:close()
    return 
  end
  while true do
    local hline
    hline, _ = client:receive("*l")
    if not hline or hline == "" then
      break
    end
  end
  local path = line:match("^%u+%s+([^%s]+)") or "/"
  local local_ip
  local_ip, _ = client:getsockname()
  local_ip = local_ip or "127.0.0.1"
  local host_part = local_ip:find(":", 1, true) and "[" .. tostring(local_ip) .. "]" or local_ip
  local redirect_url = "http://" .. tostring(host_part) .. ":" .. tostring(auth_port) .. "/"
  local resp = "HTTP/1.1 302 Found\r\nLocation: " .. tostring(redirect_url) .. "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  client:send(resp)
  local peer_ip
  peer_ip, _ = client:getpeername()
  peer_ip = tostring(peer_ip)
  local peer_mac = neigh.get_mac(peer_ip)
  if is_detection_path(path) then
    log_info({
      action = "captive_probe",
      path = path,
      ip = peer_ip,
      mac = peer_mac
    })
  else
    log_info({
      action = "captive_redirect",
      path = path,
      ip = peer_ip,
      mac = peer_mac
    })
  end
  return client:close()
end
local make_captive4
make_captive4 = function(port)
  local srv = socket.tcp()
  srv:setoption("reuseaddr", true)
  local ok, err = srv:bind("0.0.0.0", port)
  if not (ok) then
    srv:close()
    return nil, err
  end
  srv:listen(8)
  srv:settimeout(1)
  return srv
end
local make_captive6
make_captive6 = function(port)
  local ok6, srv6 = pcall(socket.tcp6)
  if not (ok6 and srv6) then
    return nil
  end
  srv6:setoption("reuseaddr", true)
  local ok62, _ = srv6:bind("::", port)
  if not (ok62) then
    srv6:close()
    return nil
  end
  srv6:listen(8)
  srv6:settimeout(1)
  return srv6
end
return {
  handle_connection = handle_connection,
  make_captive4 = make_captive4,
  make_captive6 = make_captive6
}
