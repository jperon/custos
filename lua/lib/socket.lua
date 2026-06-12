local ffi = require("ffi")
local log_debug
log_debug = require("log").log_debug
pcall(function()
  return ffi.cdef([[    typedef int socklen_t;
    typedef uint16_t sa_family_t;
    typedef unsigned int ssize_t;

    struct sockaddr {
      sa_family_t sa_family;
      char        sa_data[14];
    };

    struct sockaddr_in {
      sa_family_t sin_family;
      unsigned short sin_port;
      unsigned char  sin_addr[4];
      unsigned char  sin_zero[8];
    };

    struct sockaddr_in6 {
      sa_family_t sin6_family;
      unsigned short sin6_port;
      unsigned int   sin6_flowinfo;
      unsigned char  sin6_addr[16];
      unsigned int   sin6_scope_id;
    };

    struct sockaddr_un {
      sa_family_t sun_family;
      char        sun_path[108];
    };

    struct sockaddr_ll {
      unsigned short sll_family;
      unsigned short sll_protocol;
      int            sll_ifindex;
      unsigned short sll_hatype;
      unsigned char  sll_pkttype;
      unsigned char  sll_halen;
      unsigned char  sll_addr[8];
    };

    typedef long __fd_mask;
    struct fd_set {
      __fd_mask __fds_bits[16];
    };

    struct timeval {
      long tv_sec;
      long tv_usec;
    };

    struct pollfd {
      int   fd;
      short events;
      short revents;
    };

    int     socket(int domain, int type, int protocol);
    int     bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    int     listen(int sockfd, int backlog);
    int     accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int     connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    int     close(int fd);
    int     fcntl(int fd, int cmd, long arg);
    int     send(int sockfd, const void *buf, unsigned long len, int flags);
    int     recv(int sockfd, void *buf, unsigned long len, int flags);
    ssize_t sendto(int sockfd, const void *buf, unsigned long len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen);
    int     select(int nfds, struct fd_set *readfds, struct fd_set *writefds,
                   struct fd_set *exceptfds, struct timeval *timeout);
    int     poll(struct pollfd *fds, unsigned long nfds, int timeout);
    int     setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
    int     getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int     getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int     unlink(const char *pathname);
    unsigned int if_nametoindex(const char *ifname);
    int*    __errno_location(void);
    unsigned short htons(unsigned short h);
    unsigned int   htonl(unsigned int h);
    unsigned short ntohs(unsigned short n);
    unsigned int   ntohl(unsigned int n);
    const char*    inet_ntop(int af, const void *src, char *dst, unsigned int size);
    int            inet_pton(int af, const char *src, void *dst);
  ]])
end)
local C = ffi.C
local O_NONBLOCK, SOL_SOCKET, SO_REUSEADDR, SO_REUSEPORT
do
  local _obj_0 = require("lib.os_constants")
  O_NONBLOCK, SOL_SOCKET, SO_REUSEADDR, SO_REUSEPORT = _obj_0.O_NONBLOCK, _obj_0.SOL_SOCKET, _obj_0.SO_REUSEADDR, _obj_0.SO_REUSEPORT
end
local AF_INET = 2
local AF_INET6 = 10
local AF_UNIX = 1
local AF_PACKET = 17
local SOCK_STREAM = 1
local SOCK_DGRAM = 2
local SOCK_RAW = 3
local F_SETFL = 4
local MSG_DONTWAIT = 64
local EWOULDBLOCK = 11
local EAGAIN = 11
local ETH_P_ALL = 0x0003
local get_errno
get_errno = function()
  return ffi.C.__errno_location()[0]
end
local fd_set_clear
fd_set_clear = function(set)
  for i = 0, 15 do
    set.__fds_bits[i] = 0
  end
end
local fd_set_set
fd_set_set = function(set, fd)
  local idx = bit.rshift(fd, 6)
  local off = bit.band(fd, 63)
  set.__fds_bits[idx] = bit.bor(set.__fds_bits[idx], bit.lshift(1, off))
end
local fd_set_isset
fd_set_isset = function(set, fd)
  local idx = bit.rshift(fd, 6)
  local off = bit.band(fd, 63)
  return bit.band(set.__fds_bits[idx], bit.lshift(1, off)) ~= 0
end
local socket_mt = {
  __index = { }
}
local create_tcp
create_tcp = function()
  local fd = C.socket(AF_INET, SOCK_STREAM, 0)
  if fd < 0 then
    local errno = get_errno()
    error("socket() failed: errno=" .. errno)
  end
  local sock = {
    fd = fd,
    family = AF_INET,
    closed = false,
    timeout = nil
  }
  setmetatable(sock, socket_mt)
  return sock
end
local create_tcp6
create_tcp6 = function()
  local fd = C.socket(AF_INET6, SOCK_STREAM, 0)
  if fd < 0 then
    local errno = get_errno()
    error("socket(AF_INET6) failed: errno=" .. errno)
  end
  local sock = {
    fd = fd,
    family = AF_INET6,
    closed = false,
    timeout = nil
  }
  setmetatable(sock, socket_mt)
  return sock
end
socket_mt.__index.bind = function(self, host, port, backlog)
  if backlog == nil then
    backlog = 32
  end
  if self.closed then
    error("socket is closed")
  end
  local addr
  if self.family == AF_INET6 then
    local addr6 = ffi.new("struct sockaddr_in6")
    addr6.sin6_family = AF_INET6
    addr6.sin6_port = C.htons(port)
    if host == "*" or host == "::" or host == "0.0.0.0" then
      for i = 0, 15 do
        addr6.sin6_addr[i] = 0
      end
    else
      local ret = C.inet_pton(AF_INET6, host, addr6.sin6_addr)
      if ret <= 0 then
        error("inet_pton failed for IPv6")
      end
    end
    addr = addr6
  else
    local addr4 = ffi.new("struct sockaddr_in")
    addr4.sin_family = AF_INET
    addr4.sin_port = C.htons(port)
    if host == "*" or host == "0.0.0.0" then
      for i = 0, 3 do
        addr4.sin_addr[i] = 0
      end
    else
      local ret = C.inet_pton(AF_INET, host, addr4.sin_addr)
      if ret <= 0 then
        error("inet_pton failed for IPv4")
      end
    end
    addr = addr4
  end
  local optval = ffi.new("int[1]")
  optval[0] = 1
  C.setsockopt(self.fd, SOL_SOCKET, SO_REUSEADDR, optval, ffi.sizeof(optval))
  C.setsockopt(self.fd, SOL_SOCKET, SO_REUSEPORT, optval, ffi.sizeof(optval))
  local ret = C.bind(self.fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof(addr))
  if ret < 0 then
    local errno = get_errno()
    error("bind() failed: errno=" .. errno)
  end
  ret = C.listen(self.fd, backlog)
  if ret < 0 then
    local errno = get_errno()
    error("listen() failed: errno=" .. errno)
  end
  return true
end
socket_mt.__index.listen = function(self, backlog)
  if backlog == nil then
    backlog = 32
  end
  if self.closed then
    error("socket is closed")
  end
  local ret = C.listen(self.fd, backlog)
  if ret < 0 then
    local errno = get_errno()
    error("listen() failed: errno=" .. errno)
  end
  return true
end
socket_mt.__index.accept = function(self)
  if self.closed then
    error("socket is closed")
  end
  local addr
  if self.family == AF_INET6 then
    addr = ffi.new("struct sockaddr_in6")
  else
    addr = ffi.new("struct sockaddr_in")
  end
  local addrlen = ffi.new("socklen_t[1]")
  addrlen[0] = ffi.sizeof(addr)
  local fd = C.accept(self.fd, ffi.cast("struct sockaddr*", addr), addrlen)
  log_debug(function()
    return {
      action = "socket_accept",
      listen_fd = self.fd,
      client_fd = fd
    }
  end)
  if fd < 0 then
    local errno = get_errno()
    log_debug(function()
      return {
        action = "socket_accept_failed",
        errno = errno
      }
    end)
    if errno == EAGAIN or errno == EWOULDBLOCK then
      return nil
    end
    if errno == 4 then
      return nil
    end
    if errno == 103 then
      return nil
    end
    error("accept() failed: errno=" .. errno)
  end
  local client = {
    fd = fd,
    family = self.family,
    closed = false,
    timeout = nil
  }
  log_debug(function()
    return {
      action = "socket_created",
      fd = fd,
      family = self.family
    }
  end)
  setmetatable(client, socket_mt)
  return client
end
socket_mt.__index.connect = function(self, host, port)
  if self.closed then
    error("socket is closed")
  end
  local addr
  if self.family == AF_INET6 then
    local addr6 = ffi.new("struct sockaddr_in6")
    addr6.sin6_family = AF_INET6
    addr6.sin6_port = C.htons(port)
    local ret = C.inet_pton(AF_INET6, host, addr6.sin6_addr)
    if ret <= 0 then
      error("inet_pton failed for IPv6")
    end
    addr = addr6
  else
    local addr4 = ffi.new("struct sockaddr_in")
    addr4.sin_family = AF_INET
    addr4.sin_port = C.htons(port)
    local ret = C.inet_pton(AF_INET, host, addr4.sin_addr)
    if ret <= 0 then
      error("inet_pton failed for IPv4")
    end
    addr = addr4
  end
  local ret = C.connect(self.fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof(addr))
  if ret < 0 then
    local errno = get_errno()
    if errno == EINPROGRESS then
      return nil
    end
    error("connect() failed: errno=" .. errno)
  end
  return true
end
socket_mt.__index.send = function(self, data)
  if self.closed then
    error("socket is closed")
  end
  local n = C.send(self.fd, data, #data, MSG_DONTWAIT)
  if n < 0 then
    local errno = get_errno()
    if errno == EAGAIN or errno == EWOULDBLOCK then
      return nil
    end
    error("send() failed")
  end
  return n
end
socket_mt.__index.receive = function(self, size)
  if size == nil then
    size = 4096
  end
  if self.closed then
    error("socket is closed")
  end
  local buf = ffi.new("uint8_t[?]", size)
  local n = C.recv(self.fd, buf, size, 0)
  if n < 0 then
    local errno = get_errno()
    if errno == EAGAIN or errno == EWOULDBLOCK then
      return nil
    end
    error("recv() failed")
  end
  if n == 0 then
    return nil
  end
  return ffi.string(buf, n)
end
socket_mt.__index.settimeout = function(self, timeout)
  self.timeout = timeout
  if timeout == nil or timeout < 0 then
    C.fcntl(self.fd, F_SETFL, 0)
  else
    local flags = C.fcntl(self.fd, F_SETFL, 0)
    C.fcntl(self.fd, F_SETFL, bit.bor(flags, O_NONBLOCK))
  end
  return true
end
socket_mt.__index.setoption = function(self, option, value)
  local int_type = ffi.typeof("int")
  local int_size = ffi.sizeof(int_type)
  if option == "reuseaddr" then
    local opt_val = ffi.new("int[1]", value and 1 or 0)
    local ret = C.setsockopt(self.fd, SOL_SOCKET, SO_REUSEADDR, opt_val, int_size)
    if ret < 0 then
      local errno = get_errno()
      error("setsockopt(SO_REUSEADDR) failed: errno=" .. errno)
    end
  elseif option == "rcvtimeo" or option == "sndtimeo" then
    local SO_RCVTIMEO, SO_SNDTIMEO = 20, 21
    local opt = option == "rcvtimeo" and SO_RCVTIMEO or SO_SNDTIMEO
    local secs = tonumber(value) or 0
    local tv = ffi.new("struct timeval")
    tv.tv_sec = math.floor(secs)
    tv.tv_usec = math.floor((secs - math.floor(secs)) * 1e6)
    local ret = C.setsockopt(self.fd, SOL_SOCKET, opt, tv, ffi.sizeof(tv))
    if ret < 0 then
      local errno = get_errno()
      error("setsockopt(" .. tostring(option) .. ") failed: errno=" .. errno)
    end
  elseif option == "ipv6-v6only" then
    local IPPROTO_IPV6 = 41
    local IPV6_V6ONLY = 26
    local opt_val = ffi.new("int[1]", value and 1 or 0)
    local ret = C.setsockopt(self.fd, IPPROTO_IPV6, IPV6_V6ONLY, opt_val, int_size)
    if ret < 0 then
      local errno = get_errno()
      error("setsockopt(IPV6_V6ONLY) failed: errno=" .. errno)
    end
  else
    error("unsupported option: " .. option)
  end
  return true
end
socket_mt.__index.getpeername = function(self)
  log_debug(function()
    return {
      action = "getpeername_start",
      closed = self.closed,
      family = self.family
    }
  end)
  if self.closed then
    log_debug(function()
      return {
        action = "socket_closed"
      }
    end)
    return nil
  end
  local addr
  if self.family == AF_INET6 then
    addr = ffi.new("struct sockaddr_in6")
  else
    addr = ffi.new("struct sockaddr_in")
  end
  log_debug(function()
    return {
      action = "addr_struct_created"
    }
  end)
  local addrlen = ffi.new("socklen_t[1]")
  addrlen[0] = ffi.sizeof(addr)
  log_debug(function()
    return {
      action = "addrlen_set",
      size = addrlen[0]
    }
  end)
  local ret = C.getpeername(self.fd, ffi.cast("struct sockaddr*", addr), addrlen)
  log_debug(function()
    return {
      action = "getpeername_syscall",
      ret = ret,
      addrlen = addrlen[0]
    }
  end)
  if ret < 0 then
    log_debug(function()
      return {
        action = "getpeername_failed"
      }
    end)
    return nil
  end
  log_debug(function()
    return {
      action = "address_to_string",
      family = self.family
    }
  end)
  local buf
  if self.family == AF_INET6 then
    log_debug(function()
      return {
        action = "inet_ntop",
        family = "IPv6"
      }
    end)
    local inet6_buf = ffi.new("char[46]")
    local src_ptr = ffi.cast("const void*", addr.sin6_addr)
    local ret_ntop = C.inet_ntop(AF_INET6, src_ptr, inet6_buf, 46)
    log_debug(function()
      return {
        action = "inet_ntop_done",
        ret = tostring(ret_ntop)
      }
    end)
    buf = inet6_buf
  else
    log_debug(function()
      return {
        action = "inet_ntop",
        family = "IPv4"
      }
    end)
    local inet_buf = ffi.new("char[16]")
    local src_ptr = ffi.cast("const void*", addr.sin_addr)
    local ret_ntop = C.inet_ntop(AF_INET, src_ptr, inet_buf, 16)
    log_debug(function()
      return {
        action = "inet_ntop_done",
        ret = tostring(ret_ntop)
      }
    end)
    buf = inet_buf
  end
  log_debug(function()
    return {
      action = "buf_allocated"
    }
  end)
  local buf_ptr = ffi.cast("char*", buf)
  local result = ffi.string(buf_ptr)
  log_debug(function()
    return {
      action = "getpeername_result",
      ip = result
    }
  end)
  return result
end
socket_mt.__index.getsockname = function(self)
  if self.closed then
    return nil
  end
  local addr
  if self.family == AF_INET6 then
    addr = ffi.new("struct sockaddr_in6")
  else
    addr = ffi.new("struct sockaddr_in")
  end
  local addrlen = ffi.new("socklen_t[1]")
  addrlen[0] = ffi.sizeof(addr)
  local ret = C.getsockname(self.fd, ffi.cast("struct sockaddr*", addr), addrlen)
  if ret < 0 then
    return nil
  end
  local buf
  if self.family == AF_INET6 then
    local inet6_buf = ffi.new("char[46]")
    local src_ptr = ffi.cast("const void*", addr.sin6_addr)
    C.inet_ntop(AF_INET6, src_ptr, inet6_buf, 46)
    buf = inet6_buf
  else
    local inet_buf = ffi.new("char[16]")
    local src_ptr = ffi.cast("const void*", addr.sin_addr)
    C.inet_ntop(AF_INET, src_ptr, inet_buf, 16)
    buf = inet_buf
  end
  return ffi.string(ffi.cast("char*", buf))
end
socket_mt.__index.close = function(self)
  if not self.closed then
    C.close(self.fd)
    self.closed = true
  end
  return true
end
local socket_select
socket_select = function(readfds, writefds, timeout)
  local max_fd = 0
  local read_set = ffi.new("struct fd_set")
  local write_set = ffi.new("struct fd_set")
  fd_set_clear(read_set)
  fd_set_clear(write_set)
  if readfds then
    for _index_0 = 1, #readfds do
      local sock = readfds[_index_0]
      fd_set_set(read_set, sock.fd)
      if sock.fd > max_fd then
        max_fd = sock.fd
      end
    end
  end
  if writefds then
    for _index_0 = 1, #writefds do
      local sock = writefds[_index_0]
      fd_set_set(write_set, sock.fd)
      if sock.fd > max_fd then
        max_fd = sock.fd
      end
    end
  end
  local tv = ffi.new("struct timeval")
  if timeout then
    local sec = math.floor(timeout)
    local usec = math.floor((timeout - sec) * 1000000)
    tv.tv_sec = sec
    tv.tv_usec = usec
  end
  local ret = C.select(max_fd + 1, readfds and read_set or nil, writefds and write_set or nil, nil, timeout and tv or nil)
  if ret < 0 then
    local errno = get_errno()
    if errno == 4 then
      return { }, { }
    end
    error("select() failed: errno=" .. errno)
  end
  local ready_read = { }
  local ready_write = { }
  if readfds then
    for _index_0 = 1, #readfds do
      local sock = readfds[_index_0]
      if fd_set_isset(read_set, sock.fd) then
        table.insert(ready_read, sock)
      end
    end
  end
  if writefds then
    for _index_0 = 1, #writefds do
      local sock = writefds[_index_0]
      if fd_set_isset(write_set, sock.fd) then
        table.insert(ready_write, sock)
      end
    end
  end
  return ready_read, ready_write
end
SOL_SOCKET = 1
local SO_RCVTIMEO = 20
local SO_SNDTIMEO = 21
local htons
htons = function(n)
  local lo = n % 256
  local hi = math.floor(n / 256) % 256
  return lo * 256 + hi
end
return {
  create_tcp = create_tcp,
  create_tcp6 = create_tcp6,
  socket_select = socket_select,
  C = C,
  AF_INET = AF_INET,
  AF_INET6 = AF_INET6,
  AF_UNIX = AF_UNIX,
  AF_PACKET = AF_PACKET,
  SOCK_STREAM = SOCK_STREAM,
  SOCK_DGRAM = SOCK_DGRAM,
  SOCK_RAW = SOCK_RAW,
  ETH_P_ALL = ETH_P_ALL,
  SOL_SOCKET = SOL_SOCKET,
  SO_RCVTIMEO = SO_RCVTIMEO,
  SO_SNDTIMEO = SO_SNDTIMEO,
  htons = htons,
  get_errno = get_errno,
  tcp = create_tcp,
  tcp6 = create_tcp6,
  select = socket_select
}
