local ffi = require("ffi")
local log_debug, log_warn
do
  local _obj_0 = require("log")
  log_debug, log_warn = _obj_0.log_debug, _obj_0.log_warn
end
local C, AF_INET, AF_INET6, SOCK_DGRAM, SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO, htons
do
  local _obj_0 = require("lib.socket")
  C, AF_INET, AF_INET6, SOCK_DGRAM, SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO, htons = _obj_0.C, _obj_0.AF_INET, _obj_0.AF_INET6, _obj_0.SOCK_DGRAM, _obj_0.SOL_SOCKET, _obj_0.SO_RCVTIMEO, _obj_0.SO_SNDTIMEO, _obj_0.htons
end
local DNS_BUF_SIZE = 4096
local get_errno
get_errno = function()
  return ffi.C.__errno_location()[0]
end
local probe_ipv6
probe_ipv6 = function(ipv6_addr, port)
  if port == nil then
    port = 53
  end
  local fd = C.socket(AF_INET6, SOCK_DGRAM, 0)
  if fd < 0 then
    return false
  end
  local addr = ffi.new("struct sockaddr_in6")
  addr.sin6_family = AF_INET6
  addr.sin6_port = htons(port)
  local ret = C.inet_pton(AF_INET6, ipv6_addr, addr.sin6_addr)
  if ret <= 0 then
    C.close(fd)
    return false
  end
  local rc = C.connect(fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof(addr))
  C.close(fd)
  local ok = rc == 0
  log_debug({
    action = "probe_ipv6",
    addr = ipv6_addr,
    port = port,
    ok = ok
  })
  return ok
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
new_client = function(upstream_ip, upstream_port, timeout_ms)
  if upstream_port == nil then
    upstream_port = 53
  end
  if timeout_ms == nil then
    timeout_ms = 2000
  end
  local is_v6 = upstream_ip:find(":") ~= nil
  local family
  if is_v6 then
    family = AF_INET6
  else
    family = AF_INET
  end
  local fd = C.socket(family, SOCK_DGRAM, 0)
  if fd < 0 then
    return nil, "socket() failed: errno=" .. get_errno()
  end
  set_timeouts(fd, timeout_ms)
  if is_v6 then
    local addr = ffi.new("struct sockaddr_in6")
    addr.sin6_family = AF_INET6
    addr.sin6_port = htons(upstream_port)
    local ret = C.inet_pton(AF_INET6, upstream_ip, addr.sin6_addr)
    if ret <= 0 then
      C.close(fd)
      return nil, "inet_pton(AF_INET6) failed for " .. upstream_ip
    end
    local rc = C.connect(fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof(addr))
    if rc < 0 then
      C.close(fd)
      return nil, "connect(AF_INET6) failed: errno=" .. get_errno()
    end
  else
    local addr = ffi.new("struct sockaddr_in")
    addr.sin_family = AF_INET
    addr.sin_port = htons(upstream_port)
    local ret = C.inet_pton(AF_INET, upstream_ip, addr.sin_addr)
    if ret <= 0 then
      C.close(fd)
      return nil, "inet_pton(AF_INET) failed for " .. upstream_ip
    end
    local rc = C.connect(fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof(addr))
    if rc < 0 then
      C.close(fd)
      return nil, "connect(AF_INET) failed: errno=" .. get_errno()
    end
  end
  log_debug({
    action = "upstream_connected",
    upstream_ip = upstream_ip,
    upstream_port = upstream_port,
    family = family
  })
  return {
    fd = fd,
    family = family,
    upstream_ip = upstream_ip,
    upstream_port = upstream_port
  }
end
local query
query = function(client, dns_raw)
  log_debug({
    action = "upstream_send",
    upstream_ip = client.upstream_ip,
    bytes = #dns_raw
  })
  local n = C.send(client.fd, dns_raw, #dns_raw, 0)
  if n < 0 then
    local errno = get_errno()
    log_warn({
      action = "upstream_send_failed",
      upstream_ip = client.upstream_ip,
      errno = errno
    })
    return nil, "send() failed: errno=" .. errno
  end
  local buf = ffi.new("uint8_t[?]", DNS_BUF_SIZE)
  n = C.recv(client.fd, buf, DNS_BUF_SIZE, 0)
  if n < 0 then
    local errno = get_errno()
    log_warn({
      action = "upstream_recv_failed",
      upstream_ip = client.upstream_ip,
      errno = errno
    })
    return nil, "recv() timed out or failed: errno=" .. errno
  end
  if n == 0 then
    log_warn({
      action = "upstream_recv_empty",
      upstream_ip = client.upstream_ip
    })
    return nil, "recv() returned 0 (connection closed)"
  end
  log_debug({
    action = "upstream_recv",
    upstream_ip = client.upstream_ip,
    bytes = n
  })
  return ffi.string(buf, n)
end
local close
close = function(client)
  if client and client.fd >= 0 then
    return C.close(client.fd)
  end
end
return {
  new_client = new_client,
  query = query,
  close = close,
  probe_ipv6 = probe_ipv6
}
