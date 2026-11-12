-- src/lib/socket.moon
-- FFI wrapper for POSIX socket operations.
-- Pure FFI, no external dependencies beyond libc.

ffi = require "ffi"
{ :log_debug } = require "log"

-- Define FFI structures and functions.
-- Use pcall to handle cases where ffi_defs already defined them.
pcall ->
  ffi.cdef [[
    typedef int socklen_t;
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

    /* Conservés pour les déclarations globales LuaJIT (ffi_defs déclare les
       mêmes types ; select(2) n'est plus utilisé, socket_select passe par
       poll(2) — cf. la fin du fichier). */
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
  ]]

C = ffi.C

{ :O_NONBLOCK, :SOL_SOCKET, :SO_REUSEADDR, :SO_REUSEPORT } = require "lib.os_constants"

-- Constants
AF_INET = 2
AF_INET6 = 10
AF_UNIX = 1
AF_PACKET = 17
SOCK_STREAM = 1
SOCK_DGRAM = 2
SOCK_RAW = 3
F_SETFL = 4
MSG_DONTWAIT = 64
EWOULDBLOCK = 11
EAGAIN = 11
EINPROGRESS = 115  -- connect() non bloquant : résultat différé (select()/SO_ERROR)
ETH_P_ALL = 0x0003

-- Get errno
get_errno = -> ffi.C.__errno_location![0]

-- Bits de revents pour poll(2) (Linux).
POLLIN   = 0x1
POLLOUT  = 0x4
POLLERR  = 0x8
POLLHUP  = 0x10
POLLNVAL = 0x20

-- Socket metatable
socket_mt = {
  __index: {}
}

-- Create TCP socket
create_tcp = ->
  fd = C.socket(AF_INET, SOCK_STREAM, 0)
  if fd < 0
    errno = get_errno!
    error "socket() failed: errno="..errno

  sock = {
    :fd
    family: AF_INET
    closed: false
    timeout: nil
  }
  setmetatable sock, socket_mt
  sock

-- Create TCP6 socket
create_tcp6 = ->
  fd = C.socket(AF_INET6, SOCK_STREAM, 0)
  if fd < 0
    errno = get_errno!
    error "socket(AF_INET6) failed: errno="..errno

  sock = {
    :fd
    family: AF_INET6
    closed: false
    timeout: nil
  }
  setmetatable sock, socket_mt
  sock

-- Bind socket (supports both IPv4 and IPv6)
socket_mt.__index.bind = (host, port, backlog = 32) =>
  if @closed
    error "socket is closed"

  addr = if @family == AF_INET6
    -- IPv6 binding
    addr6 = ffi.new "struct sockaddr_in6"
    addr6.sin6_family = AF_INET6
    addr6.sin6_port = C.htons(port)

    if host == "*" or host == "::" or host == "0.0.0.0"
      for i = 0, 15
        addr6.sin6_addr[i] = 0
    else
      ret = C.inet_pton(AF_INET6, host, addr6.sin6_addr)
      if ret <= 0
        error "inet_pton failed for IPv6"
    addr6
  else
    -- IPv4 binding
    addr4 = ffi.new "struct sockaddr_in"
    addr4.sin_family = AF_INET
    addr4.sin_port = C.htons(port)

    if host == "*" or host == "0.0.0.0"
      for i = 0, 3
        addr4.sin_addr[i] = 0
    else
      ret = C.inet_pton(AF_INET, host, addr4.sin_addr)
      if ret <= 0
        error "inet_pton failed for IPv4"
    addr4

  optval = ffi.new "int[1]"
  optval[0] = 1
  C.setsockopt(@fd, SOL_SOCKET, SO_REUSEADDR, optval, ffi.sizeof(optval))
  C.setsockopt(@fd, SOL_SOCKET, SO_REUSEPORT, optval, ffi.sizeof(optval))

  ret = C.bind(@fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof(addr))
  if ret < 0
    errno = get_errno!
    error "bind() failed: errno="..errno

  ret = C.listen(@fd, backlog)
  if ret < 0
    errno = get_errno!
    error "listen() failed: errno="..errno

  true

-- Listen (standalone method)
socket_mt.__index.listen = (backlog = 32) =>
  if @closed
    error "socket is closed"

  ret = C.listen(@fd, backlog)
  if ret < 0
    errno = get_errno!
    error "listen() failed: errno="..errno

  true

-- Accept connection
socket_mt.__index.accept = =>
  if @closed
    error "socket is closed"

  addr = if @family == AF_INET6
    ffi.new "struct sockaddr_in6"
  else
    ffi.new "struct sockaddr_in"

  addrlen = ffi.new "socklen_t[1]"
  addrlen[0] = ffi.sizeof(addr)

  fd = C.accept(@fd, ffi.cast("struct sockaddr*", addr), addrlen)
  log_debug -> { action: "socket_accept", listen_fd: @fd, client_fd: fd }

  if fd < 0
    errno = get_errno!
    log_debug -> { action: "socket_accept_failed", errno: errno }
    if errno == EAGAIN or errno == EWOULDBLOCK
      return nil
    if errno == 4   -- EINTR : appel interrompu par signal, à réessayer
      return nil
    if errno == 103 -- ECONNABORTED : client RST avant accept(), bénin
      return nil
    error "accept() failed: errno="..errno

  client = {
    :fd
    family: @family
    closed: false
    timeout: nil
  }
  log_debug -> { action: "socket_created", fd: fd, family: @family }
  setmetatable client, socket_mt
  client

-- Connect
socket_mt.__index.connect = (host, port) =>
  if @closed
    error "socket is closed"

  addr = if @family == AF_INET6
    addr6 = ffi.new "struct sockaddr_in6"
    addr6.sin6_family = AF_INET6
    addr6.sin6_port = C.htons(port)

    ret = C.inet_pton(AF_INET6, host, addr6.sin6_addr)
    if ret <= 0
      error "inet_pton failed for IPv6"
    addr6
  else
    addr4 = ffi.new "struct sockaddr_in"
    addr4.sin_family = AF_INET
    addr4.sin_port = C.htons(port)

    ret = C.inet_pton(AF_INET, host, addr4.sin_addr)
    if ret <= 0
      error "inet_pton failed for IPv4"
    addr4

  ret = C.connect(@fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof(addr))

  if ret < 0
    errno = get_errno!
    if errno == EINPROGRESS
      return nil
    error "connect() failed: errno="..errno

  true

-- Send
socket_mt.__index.send = (data) =>
  if @closed
    error "socket is closed"

  n = C.send(@fd, data, #data, MSG_DONTWAIT)
  if n < 0
    errno = get_errno!
    if errno == EAGAIN or errno == EWOULDBLOCK
      return nil
    error "send() failed"
  n

-- Receive
socket_mt.__index.receive = (size = 4096) =>
  if @closed
    error "socket is closed"

  buf = ffi.new("uint8_t[?]", size)
  n = C.recv(@fd, buf, size, 0)

  if n < 0
    errno = get_errno!
    if errno == EAGAIN or errno == EWOULDBLOCK
      return nil
    error "recv() failed"

  if n == 0
    return nil

  ffi.string(buf, n)

-- Set timeout
socket_mt.__index.settimeout = (timeout) =>
  @timeout = timeout

  if timeout == nil or timeout < 0
    C.fcntl(@fd, F_SETFL, 0)
  else
    flags = C.fcntl(@fd, F_SETFL, 0)
    C.fcntl(@fd, F_SETFL, bit.bor(flags, O_NONBLOCK))

  true

-- Socket options (luasocket compatibility)
socket_mt.__index.setoption = (option, value) =>
  int_type = ffi.typeof("int")
  int_size = ffi.sizeof(int_type)

  if option == "reuseaddr"
    opt_val = ffi.new("int[1]", value and 1 or 0)
    ret = C.setsockopt(@fd, SOL_SOCKET, SO_REUSEADDR, opt_val, int_size)
    if ret < 0
      errno = get_errno!
      error "setsockopt(SO_REUSEADDR) failed: errno="..errno
  elseif option == "rcvtimeo" or option == "sndtimeo"
    -- Timeout des recv/send BLOQUANTS (SO_RCVTIMEO/SO_SNDTIMEO) : au-delà,
    -- l'appel rend EAGAIN comme en non-bloquant. Indispensable aux enfants
    -- AUTH-conn pour ne pas rester suspendus sur une connexion muette
    -- (préconnexion spéculative de navigateur, client disparu sans FIN).
    SO_RCVTIMEO, SO_SNDTIMEO = 20, 21
    opt = option == "rcvtimeo" and SO_RCVTIMEO or SO_SNDTIMEO
    secs = tonumber(value) or 0
    tv = ffi.new "struct timeval"
    tv.tv_sec  = math.floor secs
    tv.tv_usec = math.floor (secs - math.floor secs) * 1e6
    ret = C.setsockopt(@fd, SOL_SOCKET, opt, tv, ffi.sizeof tv)
    if ret < 0
      errno = get_errno!
      error "setsockopt(#{option}) failed: errno="..errno
  elseif option == "ipv6-v6only"
    IPPROTO_IPV6 = 41
    IPV6_V6ONLY = 26
    opt_val = ffi.new("int[1]", value and 1 or 0)
    ret = C.setsockopt(@fd, IPPROTO_IPV6, IPV6_V6ONLY, opt_val, int_size)
    if ret < 0
      errno = get_errno!
      error "setsockopt(IPV6_V6ONLY) failed: errno="..errno
  else
    error "unsupported option: "..option

  true

-- Get peer address (returns IP address as string)
socket_mt.__index.getpeername = =>
  log_debug -> { action: "getpeername_start", closed: @closed, family: @family }

  if @closed
    log_debug -> { action: "socket_closed" }
    return nil

  addr = if @family == AF_INET6
    ffi.new "struct sockaddr_in6"
  else
    ffi.new "struct sockaddr_in"

  log_debug -> { action: "addr_struct_created" }

  addrlen = ffi.new "socklen_t[1]"
  addrlen[0] = ffi.sizeof(addr)
  log_debug -> { action: "addrlen_set", size: addrlen[0] }

  ret = C.getpeername(@fd, ffi.cast("struct sockaddr*", addr), addrlen)
  log_debug -> { action: "getpeername_syscall", ret: ret, addrlen: addrlen[0] }

  if ret < 0
    log_debug -> { action: "getpeername_failed" }
    return nil

  -- Convert address to string
  log_debug -> { action: "address_to_string", family: @family }

  -- Allocate buffer BEFORE if/else to maintain scope
  buf = if @family == AF_INET6
    log_debug -> { action: "inet_ntop", family: "IPv6" }
    inet6_buf = ffi.new "char[46]"  -- INET6_ADDRSTRLEN
    src_ptr = ffi.cast("const void*", addr.sin6_addr)
    ret_ntop = C.inet_ntop(AF_INET6, src_ptr, inet6_buf, 46)
    log_debug -> { action: "inet_ntop_done", ret: tostring(ret_ntop) }
    inet6_buf
  else
    log_debug -> { action: "inet_ntop", family: "IPv4" }
    inet_buf = ffi.new "char[16]"  -- INET_ADDRSTRLEN
    src_ptr = ffi.cast("const void*", addr.sin_addr)
    ret_ntop = C.inet_ntop(AF_INET, src_ptr, inet_buf, 16)
    log_debug -> { action: "inet_ntop_done", ret: tostring(ret_ntop) }
    inet_buf

  log_debug -> { action: "buf_allocated" }
  buf_ptr = ffi.cast("char*", buf)
  result = ffi.string(buf_ptr)
  log_debug -> { action: "getpeername_result", ip: result }
  result

-- Get socket address (returns IP address as string)
socket_mt.__index.getsockname = =>
  if @closed
    return nil

  addr = if @family == AF_INET6
    ffi.new "struct sockaddr_in6"
  else
    ffi.new "struct sockaddr_in"

  addrlen = ffi.new "socklen_t[1]"
  addrlen[0] = ffi.sizeof(addr)

  ret = C.getsockname(@fd, ffi.cast("struct sockaddr*", addr), addrlen)
  if ret < 0
    return nil

  -- Convert address to string using if/else expression to maintain scope
  buf = if @family == AF_INET6
    inet6_buf = ffi.new "char[46]"  -- INET6_ADDRSTRLEN
    src_ptr = ffi.cast("const void*", addr.sin6_addr)
    C.inet_ntop(AF_INET6, src_ptr, inet6_buf, 46)
    inet6_buf
  else
    inet_buf = ffi.new "char[16]"  -- INET_ADDRSTRLEN
    src_ptr = ffi.cast("const void*", addr.sin_addr)
    C.inet_ntop(AF_INET, src_ptr, inet_buf, 16)
    inet_buf

  ffi.string(ffi.cast("char*", buf))

-- Close
socket_mt.__index.close = =>
  if not @closed
    C.close(@fd)
    @closed = true
  true

-- Select
--- Attend que des sockets soient prêts (équivalent de select(2)).
-- Implémenté avec poll(2) : `struct fd_set` est fait de mots `long` (4 octets
-- sur OpenWrt 32 bits, 8 sur x86-64) alors que les opérations de bits de LuaJIT
-- travaillent sur 32 bits. Un descripteur >= 32 était donc surveillé sous
-- l'identité de son alias `fd - 32` ; quand cet alias était lisible en
-- permanence (stdin = /dev/null d'un worker en service), select() rendait
-- immédiatement à chaque tour et la boucle d'acceptation consommait 100 % d'un
-- vCPU au repos (worker DoH). poll(2) n'utilise ni masque de bits ni plafond de
-- 1024 descripteurs, et accepte un timeout nul (rendu immédiat).
-- @tparam table|nil readfds  Sockets à surveiller en lecture.
-- @tparam table|nil writefds Sockets à surveiller en écriture.
-- @tparam number|nil timeout Délai en secondes (nil = attente infinie).
-- @treturn table Sockets prêts en lecture.
-- @treturn table Sockets prêts en écriture.
socket_select = (readfds, writefds, timeout) ->
  n_read  = if readfds then #readfds else 0
  n_write = if writefds then #writefds else 0
  n = n_read + n_write

  -- ffi.new refuse un tableau de taille nulle : poll() ignore les entrées
  -- au-delà de `n`, une entrée factice suffit donc quand `n` vaut 0.
  pfd = ffi.new "struct pollfd[?]", math.max n, 1
  i = 0
  if readfds
    for sock in *readfds
      pfd[i].fd = sock.fd
      pfd[i].events = POLLIN
      i += 1
  if writefds
    for sock in *writefds
      pfd[i].fd = sock.fd
      pfd[i].events = POLLOUT
      i += 1

  -- poll(2) attend des millisecondes ; nil = attente infinie.
  timeout_ms = if timeout == nil then -1 else math.max 0, math.floor(timeout * 1000 + 0.5)

  ret = C.poll pfd, n, timeout_ms
  if ret < 0
    errno = get_errno!
    if errno == 4  -- EINTR : appel interrompu par signal, retourner vide
      return {}, {}
    error "poll() failed: errno="..errno

  ready_read = {}
  ready_write = {}

  -- POLLHUP/POLLERR comptent comme « prêt » pour les deux sens, comme select(2).
  i = 0
  if readfds
    for sock in *readfds
      revents = pfd[i].revents
      error "poll() failed: invalid fd #{sock.fd}" if bit.band(revents, POLLNVAL) != 0
      if bit.band(revents, bit.bor(POLLIN, POLLHUP, POLLERR)) != 0
        table.insert ready_read, sock
      i += 1
  if writefds
    for sock in *writefds
      revents = pfd[i].revents
      error "poll() failed: invalid fd #{sock.fd}" if bit.band(revents, POLLNVAL) != 0
      if bit.band(revents, bit.bor(POLLOUT, POLLHUP, POLLERR)) != 0
        table.insert ready_write, sock
      i += 1

  ready_read, ready_write

SOL_SOCKET  = 1
SO_RCVTIMEO = 20
SO_SNDTIMEO = 21

-- Pure-Lua htons: swap bytes (little-endian, all Linux targets).
htons = (n) ->
  lo = n % 256
  hi = math.floor(n / 256) % 256
  lo * 256 + hi

{
  :create_tcp
  :create_tcp6
  :socket_select
  :C
  :AF_INET
  :AF_INET6
  :AF_UNIX
  :AF_PACKET
  :SOCK_STREAM
  :SOCK_DGRAM
  :SOCK_RAW
  :ETH_P_ALL
  :SOL_SOCKET
  :SO_RCVTIMEO
  :SO_SNDTIMEO
  :htons
  :get_errno
  tcp: create_tcp
  tcp6: create_tcp6
  select: socket_select
}
