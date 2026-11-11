local ffi = require("ffi")
local ssl = require("auth.ffi_wolfssl")
local socket = require("lib.socket")
local log_debug, log_warn
do
  local _obj_0 = require("log")
  log_debug, log_warn = _obj_0.log_debug, _obj_0.log_warn
end
local C, SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO
C, SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO = socket.C, socket.SOL_SOCKET, socket.SO_RCVTIMEO, socket.SO_SNDTIMEO
local libc = ffi.C
pcall(ffi.cdef, "struct timeval { long tv_sec; long tv_usec; };")
pcall(ffi.cdef, [[  struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    unsigned int     ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
  };
  int  getaddrinfo(const char *node, const char *service,
                   const struct addrinfo *hints, struct addrinfo **res);
  void freeaddrinfo(struct addrinfo *res);
  const char *inet_ntop(int af, const void *src, char *dst, unsigned int size);
]])
local AF_INET = 2
local AF_INET6 = 10
local MAX_DNS_BODY = 65535
local MAX_RESPONSE_BYTES = MAX_DNS_BODY + 8192
local MAX_SEND_ATTEMPTS = 100
local MAX_RECV_ATTEMPTS = 100
local MAX_RECV_ROUNDS = 32
local resolve_host
resolve_host = function(host)
  local res = ffi.new("struct addrinfo*[1]")
  local rc = libc.getaddrinfo(host, nil, nil, res)
  if rc ~= 0 then
    return nil, nil, "getaddrinfo failed (rc=" .. tostring(rc) .. ") for " .. tostring(host)
  end
  local ip4, ip6 = nil, nil
  local cur = res[0]
  while cur ~= nil do
    local buf = ffi.new("char[64]")
    if cur.ai_family == AF_INET and not ip4 then
      local src = ffi.cast("uint8_t*", cur.ai_addr)
      libc.inet_ntop(AF_INET, src + 4, buf, 64)
      ip4 = ffi.string(buf)
    elseif cur.ai_family == AF_INET6 and not ip6 then
      local src = ffi.cast("uint8_t*", cur.ai_addr)
      libc.inet_ntop(AF_INET6, src + 8, buf, 64)
      ip6 = ffi.string(buf)
    end
    cur = cur.ai_next
  end
  libc.freeaddrinfo(res[0])
  if ip4 then
    return ip4, AF_INET
  end
  if ip6 then
    return ip6, AF_INET6
  end
  return nil, nil, "no address found for " .. tostring(host)
end
local M = { }
local parse_url
parse_url = function(url)
  local rest = url:match("^https://(.+)$")
  if not (rest) then
    return nil, nil, nil
  end
  local authority, path = rest:match("^([^/]+)(/.*)$")
  if not (authority) then
    authority = rest
    path = "/dns-query"
  end
  if authority == "" then
    return nil, nil, nil
  end
  local host, port = nil, 443
  if authority:sub(1, 1) == "[" then
    local after
    host, after = authority:match("^%[([^%]]+)%](.*)$")
    if not (host and host ~= "") then
      return nil, nil, nil
    end
    if after ~= "" then
      local port_str = after:match("^:(%d+)$")
      if not (port_str) then
        return nil, nil, nil
      end
      port = tonumber(port_str)
    end
  else
    local h, port_str = authority:match("^([^:]+):(%d+)$")
    if h then
      host = h
      port = tonumber(port_str)
    else
      host = authority
    end
  end
  if not (host and #host > 0) then
    return nil, nil, nil
  end
  if not (port and port >= 1 and port <= 65535) then
    return nil, nil, nil
  end
  return host, port, path
end
local format_host_header
format_host_header = function(host, port)
  local h
  if host:find(":", 1, true) then
    h = "[" .. tostring(host) .. "]"
  else
    h = host
  end
  if port ~= 443 then
    return tostring(h) .. ":" .. tostring(port)
  else
    return h
  end
end
local set_timeouts
set_timeouts = function(fd, timeout_ms)
  local tv = ffi.new("struct timeval")
  tv.tv_sec = math.floor(timeout_ms / 1000)
  tv.tv_usec = (timeout_ms % 1000) * 1000
  C.setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv, ffi.sizeof(tv))
  return C.setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, tv, ffi.sizeof(tv))
end
local is_ip_literal
is_ip_literal = function(host)
  if host:find(":", 1, true) then
    return true
  end
  return host:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
end
local new_client
new_client = function(url, timeout_ms, verify_tls, opts)
  if timeout_ms == nil then
    timeout_ms = 2000
  end
  if verify_tls == nil then
    verify_tls = false
  end
  if opts == nil then
    opts = { }
  end
  local host, port, path = parse_url(url)
  if not (host) then
    return nil, "upstream_doh: invalid_url: " .. tostring(url)
  end
  local ca_file = nil
  if verify_tls then
    if not (type(ssl.verification_available) == "function") then
      return nil, "upstream_doh: tls_verify_unavailable: module wolfSSL sans sonde"
    end
    local available, why, ca = ssl.verification_available({
      ca_file = opts.ca_file
    })
    if not (available) then
      return nil, "upstream_doh: tls_verify_unavailable: " .. tostring(why)
    end
    ca_file = ca
  end
  local ip, family, r_err = resolve_host(host)
  if not (ip) then
    return nil, "upstream_doh: resolve_failed: " .. tostring(r_err)
  end
  local ok_s, sock = pcall(((function()
    if family == AF_INET6 then
      return socket.create_tcp6
    else
      return socket.create_tcp
    end
  end)()))
  if not (ok_s) then
    return nil, "upstream_doh: socket_create_failed: " .. tostring(sock)
  end
  set_timeouts(sock.fd, timeout_ms)
  local ok_c, c_err = pcall(function()
    return sock:connect(ip, port)
  end)
  if not (ok_c) then
    sock:close()
    return nil, "upstream_doh: connect_failed: " .. tostring(c_err)
  end
  local ok_ctx, ctx = pcall(ssl.newclient_context, {
    verify_peer = verify_tls,
    ca_file = ca_file
  })
  if not (ok_ctx) then
    sock:close()
    return nil, "upstream_doh: tls_context_failed: " .. tostring(ctx)
  end
  local sni
  if verify_tls and not is_ip_literal(host) then
    sni = host
  else
    sni = nil
  end
  local ok_wrap, tls = pcall(ssl.wrap, sock, ctx, {
    sni = sni,
    check_domain = verify_tls and host or nil
  })
  if not (ok_wrap) then
    ssl.free_context(ctx)
    sock:close()
    return nil, "upstream_doh: tls_wrap_failed: " .. tostring(tls)
  end
  local done = false
  local tls_err = nil
  for _ = 1, 50 do
    local ok_hs, hs_ret, hs_err = pcall(function()
      return tls:doconnect()
    end)
    if not (ok_hs) then
      tls_err = tostring(hs_ret)
      break
    end
    if hs_ret then
      done = true
      break
    end
    if hs_err then
      tls_err = hs_err
      break
    end
  end
  if not (done) then
    tls:close()
    ssl.free_context(ctx)
    return nil, "upstream_doh: tls_handshake_failed: " .. tostring(tls_err or 'max_attempts')
  end
  log_debug(function()
    return {
      action = "upstream_doh_connected",
      host = host,
      port = port,
      path = path
    }
  end)
  return {
    tls = tls,
    host = host,
    port = port,
    path = path,
    ctx = ctx,
    host_header = format_host_header(host, port),
    _mod = M
  }
end
local send_all
send_all = function(tls, data)
  local total = #data
  local sent = 0
  local attempts = 0
  while sent < total do
    local n = tls:send(data:sub(sent + 1))
    if n and n > 0 then
      sent = sent + n
      attempts = 0
    else
      attempts = attempts + 1
      if attempts > MAX_SEND_ATTEMPTS then
        return nil, "send_timeout"
      end
    end
  end
  return true
end
local recv_some
recv_some = function(tls)
  for _ = 1, MAX_RECV_ATTEMPTS do
    local chunk, err = tls:receive(4096)
    if chunk then
      return chunk
    end
    if err == "eof_from_peer" then
      return nil, "eof"
    end
    if not (err == "want_read_write") then
      return nil, err
    end
  end
  return nil, "recv_timeout"
end
local read_response
read_response = function(tls)
  local chunks = { }
  local total = 0
  local content_length = nil
  local hdr_end = nil
  for _ = 1, MAX_RECV_ROUNDS do
    local chunk, err = recv_some(tls)
    if not (chunk) then
      if err == "eof" then
        break
      end
      return nil, err
    end
    total = total + #chunk
    if total > MAX_RESPONSE_BYTES then
      return nil, "response_too_large"
    end
    chunks[#chunks + 1] = chunk
    local buf = table.concat(chunks)
    hdr_end = hdr_end or buf:find("\r\n\r\n", 1, true)
    if hdr_end then
      local cl = tonumber(buf:match("[Cc]ontent%-[Ll]ength:%s*(%d+)"))
      if cl then
        if cl > MAX_DNS_BODY then
          return nil, "content_length_too_large"
        end
        content_length = cl
        local body_len = #buf - hdr_end - 3
        if body_len >= cl then
          return buf
        end
      end
    end
  end
  local buf = table.concat(chunks)
  if #buf == 0 then
    return nil, "empty_response"
  end
  hdr_end = buf:find("\r\n\r\n", 1, true)
  if not (hdr_end) then
    return nil, "no_headers_end"
  end
  local body_len = #buf - hdr_end - 3
  if content_length and body_len < content_length then
    return nil, "truncated_body"
  end
  return buf
end
local query
query = function(client, dns_raw)
  if not (client and client.tls) then
    return nil, "upstream_doh: no_client"
  end
  if #dns_raw < 12 then
    return nil, "upstream_doh: short_query"
  end
  local req_txid = dns_raw:byte(1) * 256 + dns_raw:byte(2)
  local req = table.concat({
    "POST ",
    client.path,
    " HTTP/1.1\r\n",
    "Host: ",
    client.host_header or client.host,
    "\r\n",
    "Content-Type: application/dns-message\r\n",
    "Accept: application/dns-message\r\n",
    "Content-Length: ",
    tostring(#dns_raw),
    "\r\n",
    "Connection: close\r\n",
    "\r\n",
    dns_raw
  })
  local ok_send, send_ok, send_err = pcall(send_all, client.tls, req)
  if not (ok_send) then
    return nil, "upstream_doh: send_failed: " .. tostring(send_ok)
  end
  if not (send_ok) then
    return nil, "upstream_doh: send_failed: " .. tostring(send_err)
  end
  local ok_recv, buf, recv_err = pcall(read_response, client.tls)
  if not (ok_recv) then
    return nil, "upstream_doh: recv_failed: " .. tostring(buf)
  end
  if not (buf) then
    return nil, "upstream_doh: " .. tostring(recv_err)
  end
  local status = tonumber(buf:match("^HTTP/%d%.%d%s+(%d+)"))
  if not (status) then
    return nil, "upstream_doh: invalid_http_response"
  end
  if not (status == 200) then
    return nil, "upstream_doh: http_status_" .. tostring(status)
  end
  local hdr_end = buf:find("\r\n\r\n", 1, true)
  if not (hdr_end) then
    return nil, "upstream_doh: no_headers_end"
  end
  local content_length = tonumber(buf:match("[Cc]ontent%-[Ll]ength:%s*(%d+)"))
  if content_length and content_length > MAX_DNS_BODY then
    return nil, "upstream_doh: content_length_too_large"
  end
  local body = buf:sub(hdr_end + 4)
  if content_length then
    if #body < content_length then
      return nil, "upstream_doh: truncated_body"
    end
    body = body:sub(1, content_length)
  end
  if #body == 0 then
    return nil, "upstream_doh: empty_body"
  end
  if #body < 12 then
    return nil, "upstream_doh: short_response"
  end
  local resp_txid = body:byte(1) * 256 + body:byte(2)
  if not (resp_txid == req_txid) then
    return nil, "upstream_doh: txid_mismatch"
  end
  log_debug(function()
    return {
      action = "upstream_doh_response",
      host = client.host,
      body_bytes = #body
    }
  end)
  return body
end
local close
close = function(client)
  if not (client) then
    return 
  end
  if client.tls and not client.tls.closed then
    client.tls:close()
  end
  if client.ctx then
    ssl.free_context(client.ctx)
    client.ctx = nil
  end
end
local verification_available
verification_available = function(opts)
  if opts == nil then
    opts = { }
  end
  if not (type(ssl.verification_available) == "function") then
    return false, "module wolfSSL sans sonde de vérification", nil
  end
  return ssl.verification_available(opts)
end
M.new_client = new_client
M.query = query
M.close = close
M.parse_url = parse_url
M.verification_available = verification_available
return M
