-- src/lib/http.moon
-- Minimal HTTP/1.1 request reader and response writer for TLS sockets.
-- Used by auth/server.moon and worker_doh.moon.

--- Read a complete HTTP/1.1 request from a TLS socket object.
-- Reads the request line, all headers, and the body (if Content-Length > 0).
-- @tparam table client  TLS socket with :receive(pattern) method.
-- @tparam table|nil opts  { timeout: seconds } — budget TOTAL de lecture. Sans
--   lui, les retries sur want_read_write (50×) multiplient le SO_RCVTIMEO du
--   socket : une connexion muette tiendrait le processus 50 × timeout.
-- @treturn table|nil    {method, path, headers, body}, or nil + error string.
read_request = (client, opts) ->
  deadline = opts and opts.timeout and (os.time! + opts.timeout)
  receive_retry = (mode) ->
    last_err = nil
    for _ = 1, 50
      data, err = client\receive mode
      return data if data
      last_err = err
      break unless err == "want_read_write"
      -- >= : chaque want_read_write signifie qu'un SO_RCVTIMEO complet s'est
      -- déjà écoulé ; avec >, un arrondi d'horloge offrirait un tour de plus
      -- (pire cas 2× timeout au lieu de ~timeout).
      if deadline and os.time! >= deadline
        last_err = "timeout"
        break
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
  is_peer_closed_err = (err) ->
    return false unless err
    s = tostring err
    s\find("error state on socket", 1, true) or
      s\find("Peer closed underlying transport Error", 1, true) or
      s\find("eof_from_peer", 1, true)

  send_chunk = (chunk) ->
    ok, res = pcall -> client\send chunk
    if ok
      -- send rend nil sur WANT_WRITE/WANT_READ : avec SO_SNDTIMEO, cela
      -- signifie qu'un timeout complet s'est écoulé sans pouvoir écrire.
      -- L'ignorer perdrait le chunk en silence (réponse tronquée).
      return true if res
      return nil, "send_timeout"
    return nil, "peer_closed" if is_peer_closed_err res
    error tostring res

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

  ok, err = send_chunk "HTTP/1.1 #{status} #{reason}\r\n"
  return nil, err unless ok
  for name, value in pairs headers
    ok, err = send_chunk "#{name}: #{value}\r\n"
    return nil, err unless ok
  ok, err = send_chunk "\r\n"
  return nil, err unless ok
  if #body > 0
    ok, err = send_chunk body
    return nil, err unless ok
  true

{ :read_request, :send_response }
