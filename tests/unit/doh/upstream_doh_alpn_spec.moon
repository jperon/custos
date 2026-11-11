-- tests/unit/doh/upstream_doh_alpn_spec.moon
-- Poignées de main ALPN RÉELLES (vraie libwolfssl) en boucle locale :
-- 1. serveur configuré comme worker_doh (contexte + alpn_protocols) ↔ client
--    du repli DoH : h2 négocié des DEUX côtés ;
-- 2. même serveur ↔ client proposant seulement http/1.1 : http/1.1, sans échec ;
-- 3. POST DoH HTTP/2 du client du repli à travers handle_doh_client/handle_h2
--    réels (doh.query stubé : ni NFQUEUE ni fork worker superflu).
-- `pending` uniquement si la libwolfssl chargée n'expose pas ALPN (ou px5g).

ffi = require "ffi"
pcall ffi.cdef, [[
  int  fork(void);
  int  waitpid(int pid, int *status, int options);
  int  kill(int pid, int sig);
  void _exit(int status);
  int  usleep(unsigned int usec);
  void* signal(int signum, void* handler);
]]

TMP_DIR    = "tmp/h2_alpn"
CERT_FILE  = TMP_DIR .. "/cert.pem"
KEY_FILE   = TMP_DIR .. "/key.pem"
SRV_REPORT = TMP_DIR .. "/server.txt"
WNOHANG    = 1

-- Modules réels capturés au chargement du spec ; `pending` si ce sont des
-- stubs installés par une autre spec.
ssl_ok, ssl = pcall require, "auth.ffi_wolfssl"
sock_ok, socket = pcall require, "lib.socket"
mod_ok, doh_upstream = pcall require, "doh.upstream_doh"
http_ok, real_http = pcall require, "lib.http"
cert_ok, real_cert = pcall require, "auth.cert"

-- Si un autre module a déclaré `struct timeval` avant lib.socket, le bloc de
-- cdef de lib.socket échoue en entier (LuaJIT refuse de redéfinir un struct) :
-- ses méthodes lèvent alors « missing declaration for symbol 'bind' ».
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

real_modules = ssl_ok and sock_ok and mod_ok and http_ok and cert_ok and
  type(ssl.libwolfssl) != "nil" and
  type(socket.tcp) == "function" and
  type(doh_upstream.new_client) == "function" and
  type(real_http.read_request) == "function" and
  type(real_cert.load_static) == "function" and
  pcall -> type ffi.C.bind

-- ── worker_doh : chargé une fois avec doh.query/mac_learner_ipc stubés ──────
-- Ces deux modules sont destructurés au require ; on les remplace le temps du
-- chargement puis on restaure package.loaded pour ne pas polluer les autres
-- specs (worker_doh lui-même n'est pas laissé en cache).
query_handler = { fn: (raw) -> nil, "stub" }
worker_ok = nil
worker_doh = nil
do
  saved = {}
  for name in *{"worker_doh", "doh.query", "mac_learner_ipc",
                 "auth.ffi_wolfssl", "lib.socket", "lib.http", "auth.cert"}
    saved[name] = package.loaded[name]

  package.loaded["auth.ffi_wolfssl"] = ssl
  package.loaded["lib.socket"]        = socket
  package.loaded["lib.http"]          = real_http
  package.loaded["auth.cert"]         = real_cert
  package.loaded["doh.query"] = {
    process_query: (raw, ip, mac, up, vlan) -> query_handler.fn raw, ip, mac, up, vlan
  }
  package.loaded["mac_learner_ipc"] = {
    get_mac: (ip) -> nil
    get_vlan: (ip) -> nil
  }
  package.loaded["worker_doh"] = nil

  worker_ok, worker_doh = pcall require, "worker_doh"

  for name, value in pairs saved
    package.loaded[name] = value

-- ── Helpers fichiers / processus ────────────────────────────────────────────

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

-- Attend le fils sans bloquer indéfiniment (accept muet = test en échec, pas
-- une suite suspendue).
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

-- Serveur TLS dont la configuration ALPN est EXACTEMENT celle de worker_doh :
-- newcontext(cert,key) puis ctx.alpn_protocols = protocoles, wrap.
start_tls_server = (srv, protocols, handler) ->
  pid = ffi.C.fork!
  if pid == 0
    ignore_sigpipe!
    ok_child = pcall ->
      cl = srv\accept!
      ctx = ssl.newcontext { certificate: CERT_FILE, key: KEY_FILE }
      ctx.alpn_protocols = protocols
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
      sel = tls\selected_alpn!
      handler_ok = true
      if done and handler
        ok_h, herr = pcall handler, tls
        handler_ok = ok_h
        hs_err = tostring herr unless ok_h
      write_report "done=#{done and 'true' or 'false'} " ..
        "alpn=#{sel or 'nil'} handler_ok=#{handler_ok and 'true' or 'false'}" ..
        "#{hs_err and (' err=' .. hs_err) or ''}\n"
      tls\close!
      ssl.free_context ctx
    ffi.C._exit ok_child and 0 or 1
  pid

-- Client TLS brut (sans doh.upstream_doh) pour le cas http/1.1 seul.
raw_client_handshake = (port, protocols) ->
  cctx = ssl.newclient_context { verify_peer: true, ca_file: CERT_FILE }
  sock = socket.create_tcp!
  sock\connect "127.0.0.1", port
  tls = ssl.wrap sock, cctx, {
    sni: "localhost"
    check_domain: "localhost"
    alpn_protocols: protocols
  }
  done = false
  hs_err = nil
  for _ = 1, 100
    ret, err = tls\doconnect!
    if ret
      done = true
      break
    break if err
  sel = if done then tls\selected_alpn! else nil
  tls\close!
  ssl.free_context cctx
  done, sel, hs_err

-- Réponse DNS minimale corrélée au txid de la requête (le client du repli
-- vérifie le txid et la taille ≥ 12).
dns_reply = (raw) ->
  return nil, "short" if #raw < 12
  raw\sub(1, 2) .. "\x81\x80\0\x01\0\0\0\0\0\0"

dns_query = "\x12\x34\x01\x00\0\x01\0\0\0\0\0\0"
dns_query = dns_query .. "\x07example\x03com\0\0\x01\0\x01"

saved_sigpipe = nil

describe "doh.upstream_doh — ALPN réel (wolfSSL)", ->

  if not real_modules
    it "modules réels disponibles", ->
      pending "modules wolfSSL/socket/http/cert réels non disponibles (stubs) : ALPN non testable en local"
    return

  unless ssl.symbol_available("wolfSSL_UseALPN") and
         ssl.symbol_available("wolfSSL_ALPN_GetProtocol")
    it "ALPN disponible dans libwolfssl", ->
      pending "libwolfssl chargée sans wolfSSL_UseALPN/wolfSSL_ALPN_GetProtocol : test ALPN ignoré"
    return

  before_each ->
    query_handler.fn = (raw) -> dns_reply raw
    -- SIGPIPE ignoré pendant le test (écritures après fermeture du pair dans
    -- le client ou le fils), restauré ensuite.
    saved_sigpipe = ffi.C.signal 13, ffi.cast("void*", 1)

  after_each ->
    ffi.C.signal 13, saved_sigpipe if saved_sigpipe

  it "serveur production h2 ↔ client DoH : h2 négocié des deux côtés", ->
    unless gen_cert!
      pending "px5g absent ou certificat non généré : test ALPN réel ignoré"

    srv, port = open_listener!
    pid = start_tls_server srv, ssl.ALPN_PROTOCOLS, nil
    srv\close!

    h, err = doh_upstream.new_client "https://localhost:#{port}/dns-query",
      3000, true, { ca_file: CERT_FILE }
    doh_upstream.close h if h
    code = wait_child pid
    report = wait_file SRV_REPORT

    assert.is_nil err
    assert.is_not_nil h
    assert.equals "h2", h.alpn
    assert.is_true h.h2
    assert.equals 0, code
    assert.is_not_nil report
    assert.truthy report\find("done=true", 1, true)
    -- get_alpn côté serveur : même h2 que côté client.
    assert.truthy report\find("alpn=h2", 1, true)
    assert.truthy report\find("handler_ok=true", 1, true)

  it "client offrant seulement http/1.1 → http/1.1, handshake réussi", ->
    unless gen_cert!
      pending "px5g absent ou certificat non généré : test ALPN réel ignoré"

    srv, port = open_listener!
    pid = start_tls_server srv, ssl.ALPN_PROTOCOLS, nil
    srv\close!

    done, sel = raw_client_handshake port, "http/1.1"
    code = wait_child pid
    report = wait_file SRV_REPORT

    assert.is_true done
    -- wolfSSL peut rendre nil quand aucun protocole n'est marqué négocié ;
    -- l'essentiel est que http/1.1 soit choisi et le handshake réussi.
    assert.is_true sel == "http/1.1" or sel == nil
    assert.equals 0, code
    assert.is_not_nil report
    assert.truthy report\find("done=true", 1, true)
    assert.truthy report\find("alpn=http/1.1", 1, true)

  if not worker_ok
    it "worker_doh chargeable pour le test de bout en bout", ->
      pending "worker_doh non chargeable avec les modules réels : test DoH h2 ignoré"
  else
    it "POST DoH HTTP/2 via handle_doh_client réel → 200 et réponse DNS", ->
      unless gen_cert!
        pending "px5g absent ou certificat non généré : test ALPN réel ignoré"

      srv, port = open_listener!
      pid = ffi.C.fork!
      if pid == 0
        ignore_sigpipe!
        ok_child = pcall ->
          cl = srv\accept!
          worker_doh.handle_doh_client {
            client: cl
            peer_ip: "127.0.0.1"
            state: {
              static_cert_paths: { key: KEY_FILE, cert: CERT_FILE }
              cert_cache: {}
              client_timeout: 5
              upstream: nil
            }
          }
        ffi.C._exit ok_child and 0 or 1
      srv\close!

      h, err = doh_upstream.new_client "https://localhost:#{port}/dns-query",
        4000, true, { ca_file: CERT_FILE }
      assert.is_nil err
      assert.is_not_nil h
      -- Preuve que le serveur a bien annoncé h2 (sinon repli HTTP/1.1).
      assert.equals "h2", h.alpn
      assert.is_true h.h2

      body, q_err = doh_upstream.query h, dns_query
      doh_upstream.close h
      code = wait_child pid

      assert.is_nil q_err
      assert.is_not_nil body
      assert.is_true #body >= 12
      assert.equals dns_query\sub(1, 2), body\sub(1, 2)
      assert.equals 0, code
