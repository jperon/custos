-- tests/unit/auth/cert_chain_spec.moon
-- Vraie chaîne CA → intermédiaire → feuille en boucle locale : le serveur
-- WolfSSL construit par `ssl.newcontext` doit envoyer l'intermédiaire, sans
-- quoi un client qui ne fait confiance qu'à la CA racine refuse la feuille
-- (« unable to verify the first certificate »).
-- `pending` si openssl, libwolfssl ou les primitives POSIX manquent.

ffi = require "ffi"
pcall ffi.cdef, [[
  int  fork(void);
  int  waitpid(int pid, int *status, int options);
  int  kill(int pid, int sig);
  void _exit(int status);
  int  usleep(unsigned int usec);
  void* signal(int signum, void* handler);
]]

TMP_DIR   = "tmp/cert_chain"
CA_CERT   = TMP_DIR .. "/ca.crt"
CA_KEY    = TMP_DIR .. "/ca.key"
INT_CERT  = TMP_DIR .. "/int.crt"
INT_KEY   = TMP_DIR .. "/int.key"
LEAF_CERT = TMP_DIR .. "/leaf.crt"
LEAF_KEY  = TMP_DIR .. "/leaf.key"
FULLCHAIN = TMP_DIR .. "/fullchain.pem"
SRV_REPORT = TMP_DIR .. "/server.txt"
WNOHANG   = 1

ssl_ok, ssl = pcall require, "auth.ffi_wolfssl"
sock_ok, socket = pcall require, "lib.socket"

cdef_step = (code) -> pcall ffi.cdef, code
repair_socket_cdefs = ->
  cdef_step "typedef int socklen_t;"
  cdef_step "struct sockaddr { uint16_t sa_family; char sa_data[14]; };"
  cdef_step [[
    struct sockaddr_in {
      uint16_t       sin_family;
      unsigned short sin_port;
      unsigned char  sin_addr[4];
      unsigned char  sin_zero[8];
    };
  ]]
  cdef_step "int socket(int domain, int type, int protocol);"
  cdef_step "int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);"
  cdef_step "int listen(int sockfd, int backlog);"
  cdef_step "int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);"
  cdef_step "int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);"
  cdef_step "int close(int fd);"
  cdef_step "int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);"
  cdef_step "unsigned short htons(unsigned short h);"
  cdef_step "unsigned short ntohs(unsigned short h);"
  cdef_step "int inet_pton(int af, const char *src, void *dst);"
  cdef_step "int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);"
repair_socket_cdefs!

real_modules = ssl_ok and sock_ok and
  type(ssl.libwolfssl) != "nil" and
  type(ssl.newcontext) == "function" and
  type(ssl.newclient_context) == "function" and
  type(socket.tcp) == "function" and
  pcall -> type ffi.C.bind

exit_ok = (ret) -> ret == 0 or ret == true

read_file = (path) ->
  fh = io.open path, "r"
  return nil unless fh
  text = fh\read "*a"
  fh\close!
  text

wait_file = (path, tries=100) ->
  for _ = 1, tries
    text = read_file path
    return text if text and #text > 0
    ffi.C.usleep 20000
  nil

write_report = (text) ->
  fh = io.open SRV_REPORT, "w"
  return unless fh
  fh\write text
  fh\close!

gen_chain = ->
  return false unless exit_ok os.execute "command -v openssl >/dev/null 2>&1"
  os.execute "rm -rf '#{TMP_DIR}'"
  os.execute "mkdir -p '#{TMP_DIR}'"
  fh = io.open TMP_DIR .. "/ext_int.cnf", "w"
  fh\write "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
  fh\close!
  fh = io.open TMP_DIR .. "/ext_leaf.cnf", "w"
  fh\write "basicConstraints=critical,CA:FALSE\n" ..
    "keyUsage=critical,digitalSignature,keyEncipherment\n" ..
    "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n"
  fh\close!

  cmds = {
    "openssl req -x509 -newkey rsa:2048 -nodes -keyout '#{CA_KEY}' -out '#{CA_CERT}' -days 30 -subj '/CN=Test Root CA' 2>/dev/null"
    "openssl req -newkey rsa:2048 -nodes -keyout '#{INT_KEY}' -out '#{TMP_DIR}/int.csr' -subj '/CN=Test Intermediate CA' 2>/dev/null"
    "openssl x509 -req -in '#{TMP_DIR}/int.csr' -CA '#{CA_CERT}' -CAkey '#{CA_KEY}' -CAcreateserial -out '#{INT_CERT}' -days 30 -extfile '#{TMP_DIR}/ext_int.cnf' 2>/dev/null"
    "openssl req -newkey rsa:2048 -nodes -keyout '#{LEAF_KEY}' -out '#{TMP_DIR}/leaf.csr' -subj '/CN=localhost' 2>/dev/null"
    "openssl x509 -req -in '#{TMP_DIR}/leaf.csr' -CA '#{INT_CERT}' -CAkey '#{INT_KEY}' -CAcreateserial -out '#{LEAF_CERT}' -days 30 -extfile '#{TMP_DIR}/ext_leaf.cnf' 2>/dev/null"
    "cat '#{LEAF_CERT}' '#{INT_CERT}' > '#{FULLCHAIN}'"
  }
  for cmd in *cmds
    return false unless exit_ok os.execute cmd
  for path in *{CA_CERT, CA_KEY, INT_CERT, INT_KEY, LEAF_CERT, LEAF_KEY, FULLCHAIN}
    return false unless read_file(path) and #read_file(path) > 0
  true

bound_port = (sock) ->
  addr = ffi.new "struct sockaddr_in"
  addrlen = ffi.new "socklen_t[1]"
  addrlen[0] = ffi.sizeof addr
  ffi.C.getsockname sock.fd, ffi.cast("struct sockaddr*", addr), addrlen
  ffi.C.ntohs(addr.sin_port)

open_listener = ->
  srv = socket.create_tcp!
  srv\bind "127.0.0.1", 0
  srv, bound_port(srv)

wait_child = (pid, tries=400) ->
  status = ffi.new "int[1]"
  for _ = 1, tries
    done = ffi.C.waitpid pid, status, WNOHANG
    return status[0] / 256 if done == pid
    ffi.C.usleep 10000
  ffi.C.kill pid, 9
  ffi.C.waitpid pid, status, 0
  -1

ignore_sigpipe = -> pcall -> ffi.C.signal 13, ffi.cast("void*", 1)

-- Serveur TLS qui se comporte exactement comme AUTH/DoH : newcontext(cert, key).
start_tls_server = (srv, cert_file, key_file) ->
  pid = ffi.C.fork!
  if pid == 0
    ignore_sigpipe!
    ok_child = pcall ->
      cl = srv\accept!
      ctx = ssl.newcontext { certificate: cert_file, key: key_file }
      tls = ssl.wrap cl, ctx
      done = false
      hs_err = nil
      for _ = 1, 200
        ret, err = tls\dohandshake!
        if ret
          done = true
          break
        break if err and err != "want_read_write"
        ffi.C.usleep 10000
        hs_err = err
      write_report "done=#{done and 'true' or 'false'}" ..
        "#{hs_err and (' err=' .. hs_err) or ''}\n"
      tls\close!
      ssl.free_context ctx
    ffi.C._exit ok_child and 0 or 1
  pid

-- Client qui ne fait confiance QU'À la CA racine : l'intermédiaire doit venir
-- du serveur.
tls_client_check = (port) ->
  cctx = ssl.newclient_context { verify_peer: true, ca_file: CA_CERT }
  sock = socket.create_tcp!
  sock\connect "127.0.0.1", port
  tls = ssl.wrap sock, cctx, { sni: "localhost", check_domain: "localhost" }
  done = false
  hs_err = nil
  for _ = 1, 200
    ok_hs, ret, err = pcall -> tls\doconnect!
    unless ok_hs
      hs_err = tostring ret
      break
    if ret
      done = true
      break
    hs_err = err
    break if err and err != "want_read_write"
    ffi.C.usleep 10000
  tls\close!
  ssl.free_context cctx
  done, hs_err

saved_sigpipe = nil

describe "auth.ffi_wolfssl — chaîne de certificats", ->

  if not real_modules
    it "modules réels disponibles", ->
      pending "libwolfssl/socket réels non disponibles : chaîne non testable en local"
    return

  before_each ->
    saved_sigpipe = ffi.C.signal 13, ffi.cast("void*", 1)

  after_each ->
    ffi.C.signal 13, saved_sigpipe if saved_sigpipe

  it "newcontext(fullchain) envoie l'intermédiaire : vérification OK", ->
    unless gen_chain!
      pending "openssl absent ou chaîne non générée : test de chaîne ignoré"

    srv, port = open_listener!
    pid = start_tls_server srv, FULLCHAIN, LEAF_KEY
    srv\close!

    done, hs_err = tls_client_check port
    code = wait_child pid
    report = wait_file SRV_REPORT

    assert.is_true done, "handshake client échoué : #{tostring hs_err}"
    assert.equals 0, code
    assert.is_not_nil report
    assert.truthy report\find("done=true", 1, true)

  it "sans intermédiaire (feuille seule), la vérification échoue", ->
    unless gen_chain!
      pending "openssl absent ou chaîne non générée : test de chaîne ignoré"

    srv, port = open_listener!
    pid = start_tls_server srv, LEAF_CERT, LEAF_KEY
    srv\close!

    done = tls_client_check port
    wait_child pid

    assert.is_false done
