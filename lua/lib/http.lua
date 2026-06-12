local read_request
read_request = function(client, opts)
  local deadline = opts and opts.timeout and (os.time() + opts.timeout)
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
      if deadline and os.time() >= deadline then
        last_err = "timeout"
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
  local is_peer_closed_err
  is_peer_closed_err = function(err)
    if not (err) then
      return false
    end
    local s = tostring(err)
    return s:find("error state on socket", 1, true) or s:find("Peer closed underlying transport Error", 1, true) or s:find("eof_from_peer", 1, true)
  end
  local send_chunk
  send_chunk = function(chunk)
    local ok, res = pcall(function()
      return client:send(chunk)
    end)
    if ok then
      if res then
        return true
      end
      return nil, "send_timeout"
    end
    if is_peer_closed_err(res) then
      return nil, "peer_closed"
    end
    return error(tostring(res))
  end
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
  local ok, err = send_chunk("HTTP/1.1 " .. tostring(status) .. " " .. tostring(reason) .. "\r\n")
  if not (ok) then
    return nil, err
  end
  for name, value in pairs(headers) do
    ok, err = send_chunk(tostring(name) .. ": " .. tostring(value) .. "\r\n")
    if not (ok) then
      return nil, err
    end
  end
  ok, err = send_chunk("\r\n")
  if not (ok) then
    return nil, err
  end
  if #body > 0 then
    ok, err = send_chunk(body)
    if not (ok) then
      return nil, err
    end
  end
  return true
end
return {
  read_request = read_request,
  send_response = send_response
}
