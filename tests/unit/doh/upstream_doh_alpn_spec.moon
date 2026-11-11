-- tests/unit/doh/upstream_doh_alpn_spec.moon
-- Négociation ALPN réelle du client DoH de repli : serveur wolfSSL en boucle
-- locale (127.0.0.1, port éphémère, certificat généré dans ./tmp/), client via
-- doh.upstream_doh.new_client. Prouve que le serveur annonce h2 et que le
-- client le négocie. Si libwolfssl n'expose pas ALPN, le test est `pending`.

ffi = require "ffi"
pcall ffi.cdef, [[
  int  fork(void);
  int  waitpid(int pid, int *status, int options);
  void _exit(int status);
  int  usleep(unsigned int usec);
  void* signal(int signum, void* handler);
]]

TMP_DIR   = "tmp/h2_alpn"
CERT_FILE = TMP_DIR .. "/cert.pem"
KEY_FILE  = TMP_DIR .. "/key.pem"
SRV_REPORT = TMP_DIR .. "/server.txt"

-- Modules capturés au chargement du spec ; le test est `pending` si ce sont
-- des stubs (d'autres specs remplacent package.loaded).
ssl_ok, ssl = pcall require, "auth.ffi_wolfssl"
sock_ok, socket = pcall require, "lib.socket"
mod_ok, doh_upstream = pcall require, "doh.upstream_doh"

-- Si un autre module a déclaré `struct timeval` avant lib.socket, le bloc de
-- cdef de lib.socket échoue en entier (LuaJIT refuse de redéfinir un struct) :
-- ses méthodes lèvent alors « missing declaration for symbol 'bind' ». On
-- répare les seules déclarations utilisées par ce test, chacune isolément.
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

real_modules = ssl_ok and sock_ok and mod_ok and
  type(ssl.libwolfssl) != "nil" and
  type(socket.tcp) == "function" and
  type(doh_upstream.new_client) == "function" and
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

gen_cert = ->
  return false unless exit_ok os.execute "command -v px5g >/dev/null 2>&1"
  os.execute "mkdir -p #{TMP_DIR}"
  os.remove CERT_FILE
  os.remove KEY_FILE
  os.remove SRV_REPORT
  cmd = "px5g selfsigned -newkey ec -keyout '#{KEY_FILE}' -out '#{CERT_FILE}' " ..
    "-subj '/CN=localhost' 2>/dev/null"
  return false unless exit_ok os.execute cmd
  cert = read_file CERT_FILE
  key = read_file KEY_FILE
  cert and key and #cert > 0 and #key > 0

-- Port effectif d'un socket déjà bind()é (bind port 0 → port éphémère).
bound_port = (sock) ->
  addr = ffi.new "struct sockaddr_in"
  addrlen = ffi.new "socklen_t[1]"
  addrlen[0] = ffi.sizeof addr
  ffi.C.getsockname sock.fd, ffi.cast("struct sockaddr*", addr), addrlen
  ffi.C.ntohs(addr.sin_port)

describe "doh.upstream_doh — ALPN réel (wolfSSL)", ->

  if not real_modules
    it "modules réels disponibles", ->
      pending "modules wolfSSL/socket réels non disponibles (stubs) : ALPN non testable en local"
    return

  unless ssl.symbol_available("wolfSSL_UseALPN") and
         ssl.symbol_available("wolfSSL_ALPN_GetProtocol")
    it "ALPN disponible dans libwolfssl", ->
      pending "libwolfssl chargée sans wolfSSL_UseALPN/wolfSSL_ALPN_GetProtocol : test ALPN ignoré"
    return

  it "le serveur annonce h2 et le client le négocie (handshake réel)", ->
    unless gen_cert!
      pending "px5g absent ou certificat non généré : test ALPN réel ignoré"

    srv = socket.create_tcp!
    srv\bind "127.0.0.1", 0
    port = bound_port srv
    assert.is_true port > 0

    pid = ffi.C.fork!
    if pid == 0
      -- Processus fils : serveur TLS unique. _exit évite de poursuivre Busted.
      -- SIGPIPE ignoré : une fermeture prématurée du client ne doit pas tuer
      -- le fils avant qu'il n'écrive son rapport.
      pcall -> ffi.C.signal 13, ffi.cast("void*", 1)
      ok_child = pcall ->
        cl = srv\accept!
        ctx = ssl.newcontext { certificate: CERT_FILE, key: KEY_FILE }
        tls = ssl.wrap cl, ctx
        -- Annonce serveur h2 avec l'option CONTINUE_ON_MISMATCH correcte (2).
        ssl.alpn_configure_client ssl.libwolfssl, tls.ssl, ssl.CLIENT_ALPN_PROTOCOLS
        done = false
        for _ = 1, 200
          ret, hs_err = tls\dohandshake!
          if ret
            done = true
            break
          break if hs_err and hs_err != "want_read_write"
          ffi.C.usleep 10000
        sel = tls\selected_alpn!
        write_report "done=#{done and 'true' or 'false'} alpn=#{sel or 'nil'}\n"
        tls\close!
        ssl.free_context ctx
      ffi.C._exit ok_child and 0 or 1

    -- Parent : le serveur écoute déjà (bind+listen avant fork).
    h, err = doh_upstream.new_client "https://localhost:#{port}/dns-query", 3000, true,
      { ca_file: CERT_FILE }
    doh_upstream.close h if h
    status = ffi.new "int[1]"
    ffi.C.waitpid pid, status, 0
    report = wait_file SRV_REPORT

    assert.is_nil err
    assert.is_not_nil h
    assert.equals "h2", h.alpn
    assert.is_true h.h2
    assert.equals 0, status[0] / 256
    assert.is_not_nil report
    assert.truthy report\find("done=true", 1, true)
    assert.truthy report\find("alpn=h2", 1, true)
