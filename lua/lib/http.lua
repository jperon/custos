local read_request
read_request = function(client)
  local receive_retry
  receive_retry = function(mode)
    local last_err = nil
    for _ = 1, 50 do
      local data, err = client:receive(mode)
      if data then
        return data
      end
      last_err = err
      if not (err == "want_read_write") then
        break
      end
    end
    return nil, last_err
  end
  local request_line, err = receive_retry("*l")
  if not (request_line) then
    return nil, err or "connection_closed_or_timeout"
  end
  local method, path = request_line:match("^(%w+)%s+([^%s]+)%s+HTTP")
  if not (method and path) then
    return nil, "bad_request_line"
  end
  local headers = { }
  local content_length = 0
  while true do
    local line, line_err = receive_retry("*l")
    if not (line) then
      return nil, line_err or "header_read_error"
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
    body = receive_retry(content_length)
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
  elseif 415 == _exp_0 then
    reason = "Unsupported Media Type"
  elseif 502 == _exp_0 then
    reason = "Bad Gateway"
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
return {
  read_request = read_request,
  send_response = send_response
}
