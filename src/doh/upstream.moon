-- src/doh/upstream.moon
-- Minimal UDP DNS client for forwarding DoH queries to a plain DNS resolver.

ffi = require "ffi"
{ :log_debug, :log_warn } = require "log"
{ :C, :AF_INET, :AF_INET6, :SOCK_DGRAM, :SOL_SOCKET, :SO_RCVTIMEO, :SO_SNDTIMEO, :htons } = require "lib.socket"

-- Maximum DNS UDP response size (EDNS0 extended, safe upper bound).
DNS_BUF_SIZE = 4096

get_errno = -> ffi.C.__errno_location![0]

--- Probe whether an IPv6 socket can connect to a given address.
-- Used at startup to determine upstream address family preference.
-- @tparam string ipv6_addr IPv6 address string.
-- @tparam number port      UDP port (typically 53).
-- @treturn boolean true if the connect() syscall succeeds.
probe_ipv6 = (ipv6_addr, port=53) ->
  fd = C.socket AF_INET6, SOCK_DGRAM, 0
  return false if fd < 0
  addr = ffi.new "struct sockaddr_in6"
  addr.sin6_family = AF_INET6
  addr.sin6_port   = htons port
  ret = C.inet_pton AF_INET6, ipv6_addr, addr.sin6_addr
  if ret <= 0
    C.close fd
    log_warn -> { action: "probe_ipv6_failed", addr: ipv6_addr, port: port, reason: "inet_pton_failed" }
    return false
  rc = C.connect fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof(addr)
  C.close fd
  ok = rc == 0
  unless ok
    log_warn -> { action: "probe_ipv6_failed", addr: ipv6_addr, port: port, reason: "connect_failed", errno: get_errno! }
  log_debug -> { action: "probe_ipv6", addr: ipv6_addr, port: port, ok: ok }
  ok

--- Set SO_RCVTIMEO and SO_SNDTIMEO on a socket fd.
-- @tparam number fd          Socket file descriptor.
-- @tparam number timeout_ms  Timeout in milliseconds.
-- @treturn nil
set_timeouts = (fd, timeout_ms) ->
  tv = ffi.new "struct timeval"
  tv.tv_sec  = math.floor timeout_ms / 1000
  tv.tv_usec = (timeout_ms % 1000) * 1000
  C.setsockopt fd, SOL_SOCKET, SO_RCVTIMEO, tv, ffi.sizeof(tv)
  C.setsockopt fd, SOL_SOCKET, SO_SNDTIMEO, tv, ffi.sizeof(tv)

--- Create a connected UDP socket pointing at the given upstream DNS server.
-- @tparam string upstream_ip   IPv4 or IPv6 address of the DNS server.
-- @tparam number upstream_port UDP port (default 53).
-- @tparam number timeout_ms    Send/recv timeout in milliseconds (default 2000).
-- @treturn table|nil  Client handle {fd, family}, or nil + error string.
new_client = (upstream_ip, upstream_port=53, timeout_ms=2000) ->
  is_v6 = upstream_ip\find":" != nil
  family = if is_v6 then AF_INET6 else AF_INET

  fd = C.socket family, SOCK_DGRAM, 0
  if fd < 0
    return nil, "socket() failed: errno=" .. get_errno!

  set_timeouts fd, timeout_ms

  if is_v6
    addr = ffi.new "struct sockaddr_in6"
    addr.sin6_family = AF_INET6
    addr.sin6_port   = htons upstream_port
    ret = C.inet_pton AF_INET6, upstream_ip, addr.sin6_addr
    if ret <= 0
      C.close fd
      return nil, "inet_pton(AF_INET6) failed for " .. upstream_ip
    rc = C.connect fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof(addr)
    if rc < 0
      C.close fd
      return nil, "connect(AF_INET6) failed: errno=" .. get_errno!
  else
    addr = ffi.new "struct sockaddr_in"
    addr.sin_family = AF_INET
    addr.sin_port   = htons upstream_port
    ret = C.inet_pton AF_INET, upstream_ip, addr.sin_addr
    if ret <= 0
      C.close fd
      return nil, "inet_pton(AF_INET) failed for " .. upstream_ip
    rc = C.connect fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof(addr)
    if rc < 0
      C.close fd
      return nil, "connect(AF_INET) failed: errno=" .. get_errno!

  log_debug -> { action: "upstream_connected", :upstream_ip, :upstream_port, :family, :fd }
  { :fd, :family, :upstream_ip, :upstream_port }

--- Send a raw DNS query and wait for the response.
-- The socket must have been created with new_client().
-- A new socket is NOT created per query; the caller reuses the client handle.
-- @tparam table  client   Handle returned by new_client().
-- @tparam string dns_raw  Raw DNS query bytes (wire format).
-- @treturn string|nil  Raw DNS response bytes, or nil + error string.
query = (client, dns_raw) ->
  log_debug -> { action: "upstream_send", upstream_ip: client.upstream_ip, bytes: #dns_raw }
  n = C.send client.fd, dns_raw, #dns_raw, 0
  if n < 0
    errno = get_errno!
    log_warn -> { action: "upstream_send_failed", upstream_ip: client.upstream_ip, errno: errno }
    return nil, "send() failed: errno=" .. errno

  buf = ffi.new "uint8_t[?]", DNS_BUF_SIZE
  n = C.recv client.fd, buf, DNS_BUF_SIZE, 0
  if n < 0
    errno = get_errno!
    log_warn -> { action: "upstream_recv_failed", upstream_ip: client.upstream_ip, errno: errno }
    return nil, "recv() timed out or failed: errno=" .. errno
  if n == 0
    log_warn -> { action: "upstream_recv_empty", upstream_ip: client.upstream_ip }
    return nil, "recv() returned 0 (connection closed)"

  log_debug -> { action: "upstream_recv", upstream_ip: client.upstream_ip, bytes: n }
  ffi.string buf, n

--- Close the UDP socket held by a client handle.
-- @tparam table client Handle returned by new_client().
-- @treturn nil
close = (client) ->
  C.close client.fd if client and client.fd >= 0

{ :new_client, :query, :close, :probe_ipv6 }
