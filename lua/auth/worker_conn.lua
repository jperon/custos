local log_info
log_info = require("log").log_info
local build_ipc_message
build_ipc_message = function(type, ip, mac, body)
  if #ip == 4 then
    ip = string.rep("\0", 12) .. ip
  end
  if mac == "unknown" then
    mac = string.rep("\xFF", 6)
  end
  local body_len = #body
  return string.pack(">c16c6H2", type, ip, mac, body_len) .. body
end
local parse_ipc_response
parse_ipc_response = function(data)
  local status = data:byte(1) * 256 + data:byte(2)
  local headers_len = data:byte(3) * 256 + data:byte(4)
  local body_len = data:byte(5) * 256 * 256 * 256 + data:byte(6) * 256 * 256 + data:byte(7) * 256 + data:byte(8)
  local headers_str
  if headers_len > 0 then
    headers_str = data:sub(9, 8 + headers_len)
  else
    headers_str = ""
  end
  local body_data
  if body_len > 0 then
    body_data = data:sub(9 + headers_len, 8 + headers_len + body_len)
  else
    body_data = ""
  end
  local headers = { }
  local h_pos = 1
  while h_pos <= headers_len do
    local name_len = headers_str:byte(h_pos)
    h_pos = h_pos + 1
    local name = headers_str:sub(h_pos, h_pos + name_len - 1)
    h_pos = h_pos + name_len
    local value_len = headers_str:byte(h_pos)
    h_pos = h_pos + 1
    local value = headers_str:sub(h_pos, h_pos + value_len - 1)
    h_pos = h_pos + value_len
    headers[name] = value
  end
  return status, headers, body_data
end
local handle_connection
handle_connection = function(client_sock, peer_ip, peer_mac)
  client_sock:settimeout(10)
  local req = client_sock:receive("*l")
  if not (req) then
    client_sock:close()
    return 
  end
  local method, path = req:match("^(%w+)%s+([^%s]+)%s+HTTP")
  if not (method and path) then
    client_sock:send("HTTP/1.1 404 Not Found\r\nContent-Length: 12\r\n\r\n<h1>404</h1>")
    client_sock:close()
    return 
  end
  local body = ""
  local content_length = 0
  while true do
    local line = client_sock:receive("*l")
    if not (line) then
      break
    end
    if line:lower():match("^content%-length:%s*(%d+)$") then
      content_length = tonumber(line:match("%d+"))
    end
    if line == "" then
      break
    end
  end
  if content_length > 0 then
    body = client_sock:receive(content_length)
  end
  local ipc_type
  if path == "/login" then
    ipc_type = 0x01
  elseif path == "/ping" then
    ipc_type = 0x02
  elseif path == "/logout" then
    ipc_type = 0x03
  elseif path == "/register" then
    ipc_type = 0x04
  else
    client_sock:send("HTTP/1.1 404 Not Found\r\nContent-Length: 12\r\n\r\n<h1>404</h1>")
    client_sock:close()
    return 
  end
  local ipc_msg = build_ipc_message(ipc_type, peer_ip, peer_mac, body)
  io.stdout:write(ipc_msg)
  io.stdout:flush()
  local response_data = io.stdin:read(8)
  if not (response_data) then
    client_sock:close()
    return 
  end
  local status, headers, body_data = parse_ipc_response(response_data)
  local http_response = "HTTP/1.1 " .. status .. " OK\r\n"
  for name, value in pairs(headers) do
    http_response = http_response .. name .. ": " .. value .. "\r\n"
  end
  http_response = http_response .. "\r\n" .. body_data
  client_sock:send(http_response)
  return client_sock:close()
end
local main
main = function()
  local peer_ip = arg[1] or "unknown"
  local peer_mac = arg[2] or "unknown"
  return handle_connection(io.stdin, peer_ip, peer_mac)
end
return main()
