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
  local host, port_str, path = url:match("^https://([^/:]+):(%d+)(/.+)$")
  if host then
    return host, tonumber(port_str), path
  end
  host, path = url:match("^https://([^/]+)(/.+)$")
  if host then
    return host, 443, path
  end
  host = url:match("^https://([^/]+)$")
  if host then
    return host, 443, "/dns-query"
  end
  return nil, nil, nil
end
local set_timeouts
set_timeouts = function(fd, timeout_ms)
  local tv = ffi.new("struct timeval")
  tv.tv_sec = math.floor(timeout_ms / 1000)
  tv.tv_usec = (timeout_ms % 1000) * 1000
  C.setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, tv, ffi.sizeof(tv))
  return C.setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, tv, ffi.sizeof(tv))
end
local new_client
new_client = function(url, timeout_ms, verify_tls)
  if timeout_ms == nil then
    timeout_ms = 2000
  end
  if verify_tls == nil then
    verify_tls = false
  end
  local host, port, path = parse_url(url)
  if not (host) then
    return nil, "upstream_doh: invalid_url: " .. tostring(url)
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
  local ctx = ssl.newclient_context({
    verify_peer = verify_tls
  })
  local tls = ssl.wrap(sock, ctx)
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
    path = path,
    _mod = M
  }
end
local query
query = function(client, dns_raw)
  local tls = client.tls
  local host = client.host
  local path = client.path
  local req = table.concat({
    "POST ",
    path,
    " HTTP/1.1\r\n",
    "Host: ",
    host,
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
  local ok_send, send_err = pcall(function()
    return tls:send(req)
  end)
  if not (ok_send) then
    return nil, "upstream_doh: send_failed: " .. tostring(send_err)
  end
  local chunks = { }
  local content_length = nil
  for _ = 1, 20 do
    local chunk = nil
    for _ = 1, 50 do
      local c, recv_err = tls:receive(4096)
      if c then
        chunk = c
        break
      end
      if recv_err ~= "want_read_write" then
        break
      end
    end
    if not (chunk) then
      break
    end
    chunks[#chunks + 1] = chunk
    local buf = table.concat(chunks)
    local hdr_end = buf:find("\r\n\r\n", 1, true)
    if hdr_end then
      local cl = tonumber(buf:match("[Cc]ontent%-[Ll]ength:%s*(%d+)"))
      content_length = cl
      local body_len = #buf - hdr_end - 3
      if not cl or body_len >= cl then
        break
      end
    end
  end
  local buf = table.concat(chunks)
  if not (#buf > 0) then
    return nil, "upstream_doh: empty_response"
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
  local body = buf:sub(hdr_end + 4)
  if content_length and content_length < #body then
    body = body:sub(1, content_length)
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
  if client and client.tls and not client.tls.closed then
    return client.tls:close()
  end
end
M.new_client = new_client
M.query = query
M.close = close
return M
