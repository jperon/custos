-- src/lib/http.moon
-- Minimal HTTP/1.1 request reader and response writer for TLS sockets.
-- Used by auth/server.moon and worker_doh.moon.

--- Read a complete HTTP/1.1 request from a TLS socket object.
-- Reads the request line, all headers, and the body (if Content-Length > 0).
-- @tparam table client  TLS socket with :receive(pattern) method.
-- @treturn table|nil    {method, path, headers, body}, or nil + error string.
read_request = (client) ->
  receive_retry = (mode) ->
    last_err = nil
    for _ = 1, 50
      data, err = client\receive mode
      return data if data
      last_err = err
      break unless err == "want_read_write"
    nil, last_err

  request_line, err = receive_retry "*l"
  unless request_line
    return nil, err or "connection_closed_or_timeout"

  method, path = request_line\match "^(%w+)%s+([^%s]+)%s+HTTP"
  return nil, "bad_request_line" unless method and path

  headers = {}
  content_length = 0

  while true
    line, line_err = receive_retry "*l"
    unless line
      return nil, line_err or "header_read_error"
    break if line == ""

    name, value = line\match "^([^:]+):%s*(.*)$"
    if name
      lname = name\lower!
      headers[lname] = value
      if lname == "content-length"
        content_length = tonumber(value) or 0

  body = ""
  if content_length > 0
    body = receive_retry content_length
    body = body or ""

  { :method, :path, :headers, :body }

--- Write an HTTP/1.1 response to a TLS socket object.
-- Always appends Content-Length and Connection: close unless supplied.
-- @tparam table  client  TLS socket with :send(str) method.
-- @tparam number status  HTTP status code.
-- @tparam table  headers Response headers table (key → value strings).
-- @tparam string body    Response body (may be empty string).
-- @treturn nil
send_response = (client, status, headers, body) ->
  body or= ""
  reason = switch status
    when 200 then "OK"
    when 204 then "No Content"
    when 302 then "Found"
    when 400 then "Bad Request"
    when 401 then "Unauthorized"
    when 404 then "Not Found"
    when 409 then "Conflict"
    when 415 then "Unsupported Media Type"
    when 502 then "Bad Gateway"
    else "Internal Server Error"

  headers or= {}
  headers["Content-Length"] = tostring #body unless headers["Content-Length"]
  headers["Connection"] = "close" unless headers["Connection"]

  client\send "HTTP/1.1 #{status} #{reason}\r\n"
  for name, value in pairs headers
    client\send "#{name}: #{value}\r\n"
  client\send "\r\n"
  client\send body if #body > 0

{ :read_request, :send_response }
