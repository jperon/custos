-- src/auth/ffi_wolfssl.moon
-- FFI wrapper for WolfSSL (libwolfssl) TLS/SSL library.

ffi = require "ffi"
{ :log_debug } = require "log"
{ :get_errno } = require "lib.socket"

ffi.cdef [[
  typedef struct WOLFSSL_CTX WOLFSSL_CTX;
  typedef struct WOLFSSL WOLFSSL;
  typedef struct WOLFSSL_METHOD WOLFSSL_METHOD;

  WOLFSSL_METHOD* wolfTLS_server_method(void);
  WOLFSSL_METHOD* wolfTLS_client_method(void);
  WOLFSSL_METHOD* wolfSSLv23_server_method(void);

  WOLFSSL_CTX* wolfSSL_CTX_new(WOLFSSL_METHOD *method);
  void         wolfSSL_CTX_free(WOLFSSL_CTX *ctx);
  int          wolfSSL_CTX_use_certificate_file(WOLFSSL_CTX *ctx, const char *file, int type);
  int          wolfSSL_CTX_use_certificate_chain_file(WOLFSSL_CTX *ctx, const char *file);
  int          wolfSSL_CTX_use_PrivateKey_file(WOLFSSL_CTX *ctx, const char *file, int type);

  WOLFSSL* wolfSSL_new(WOLFSSL_CTX *ctx);
  void     wolfSSL_free(WOLFSSL *ssl);
  int      wolfSSL_set_fd(WOLFSSL *ssl, int fd);

  int wolfSSL_connect(WOLFSSL *ssl);
  int wolfSSL_accept(WOLFSSL *ssl);
  int wolfSSL_write(WOLFSSL *ssl, const void *data, int sz);
  int wolfSSL_read(WOLFSSL *ssl, void *data, int sz);
  int wolfSSL_shutdown(WOLFSSL *ssl);
  int wolfSSL_get_error(WOLFSSL *ssl, int ret);
  void wolfSSL_CTX_set_verify(WOLFSSL_CTX *ctx, int mode, void *verify_callback);
  int wolfSSL_CTX_load_verify_locations(WOLFSSL_CTX *ctx, const char *file, const char *path);
  int wolfSSL_UseSNI(WOLFSSL *ssl, unsigned char type, const void *data, unsigned short size);
  int wolfSSL_check_domain_name(WOLFSSL *ssl, const char *dn);
  int wolfSSL_CTX_UseALPN(WOLFSSL_CTX *ctx, char *protocol_name_list,
                          unsigned int protocol_name_listSz, unsigned char options);
  int wolfSSL_UseALPN(WOLFSSL *ssl, char *protocol_name_list,
                      unsigned int protocol_name_listSz, unsigned char options);
  int wolfSSL_ALPN_GetProtocol(WOLFSSL *ssl, char **protocol_name, unsigned short *size);
  unsigned long wolfSSL_ERR_get_error(void);
  char* wolfSSL_ERR_reason_error_string(unsigned long err);
]]

-- Load library with multiple fallback strategies
libwolfssl = nil

-- Strategy 1: Try common names (works if ldconfig is configured)
for _, name in ipairs({"libwolfssl.so.5.8.4.e624513f", "libwolfssl.so.5", "libwolfssl.so.44", "wolfssl", "libwolfssl.so"})
  ok, lib = pcall(ffi.load, name)
  if ok
    libwolfssl = lib
    break

-- Strategy 2: scan LD_LIBRARY_PATH directories then standard paths
if not libwolfssl
  dirs = {}
  for p in (os.getenv("LD_LIBRARY_PATH") or "")\gmatch("[^:]+")
    dirs[#dirs + 1] = p
  for _, p in ipairs({"/usr/lib", "/lib", "/usr/local/lib"})
    dirs[#dirs + 1] = p
  search = table.concat(dirs, " ")
  f = io.popen("find #{search} -name 'libwolfssl*.so*' -type f 2>/dev/null | sort -V | tail -1")
  path = f\read("*a")\gsub("\n", "")
  f\close!
  if path and path ~= ""
    ok, lib = pcall(ffi.load, path)
    libwolfssl = lib if ok

if not libwolfssl
  error "libwolfssl not found in: /usr/lib, /lib, LD_LIBRARY_PATH, or standard search paths"

-- Error codes
SSL_ERROR_NONE = 0
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_ERROR_SSL = 1
SSL_VERIFY_NONE = 0
SSL_VERIFY_PEER = 1

-- SNI (wolfSSL_UseSNI) et magasins de CA usuels (OpenWrt, Debian, Alpine, RHEL).
WOLFSSL_SNI_HOST_NAME = 0
CA_FILE_CANDIDATES = {
  "/etc/ssl/certs/ca-certificates.crt"
  "/etc/ssl/cert.pem"
  "/etc/pki/tls/certs/ca-bundle.crt"
  "/etc/ssl/ca-bundle.pem"
}

-- File types
SSL_FILETYPE_PEM = 1
SSL_FILETYPE_ASN1 = 2
WOLFSSL_ALPN_CONTINUE_ON_MISMATCH = 0x01
-- Liste ALPN annoncée par le serveur (wolfSSL attend une liste séparée par
-- des virgules, pas le format wire TLS). `ALPN_PROTOCOLS` est le jeu opt-in du
-- serveur DoH ; `DEFAULT_ALPN_PROTOCOLS` reste celui du portail AUTH (HTTP/1.1).
ALPN_PROTOCOLS = "h2,http/1.1"
DEFAULT_ALPN_PROTOCOLS = "http/1.1"
_alpn_available = nil

--- Extract WolfSSL error queue messages
get_ssl_errors = () ->
  errors = {}
  while true
    err = libwolfssl.wolfSSL_ERR_get_error!
    break if err == 0
    reason_ptr = libwolfssl.wolfSSL_ERR_reason_error_string(err)
    reason = if reason_ptr != nil then ffi.string(reason_ptr) else "unknown"
    table.insert errors, "#{err}:#{reason}"
  table.concat errors, " | "

-- SSL object metatable
ssl_mt = {
  __index: {}
}

--- Teste si un symbole est réellement résolu par la libwolfssl chargée.
-- Sur OpenWrt, la lib peut être compilée sans certaines options : un `cdef`
-- déclaré ne garantit pas que le symbole existe (dlsym échoue à l'accès).
-- @tparam string name Nom du symbole C.
-- @tparam table|nil lib Bibliothèque à sonder (défaut : libwolfssl).
-- @treturn boolean true si le symbole est résolvable.
symbol_available = (name, lib) ->
  lib or= libwolfssl
  pcall -> lib[name]

--- Teste l'existence lisible d'un fichier (sans shell).
-- @tparam string path Chemin candidat.
-- @treturn boolean true si le fichier peut être ouvert en lecture.
ca_file_readable = (path) ->
  return false if type(path) != "string" or #path == 0
  f = io.open path, "r"
  return false unless f
  f\close!
  true

--- Localise un magasin de CA : chemin explicite, SSL_CERT_FILE, puis chemins usuels.
-- @tparam string|nil explicit Chemin configuré (doh.upstream_fallback_ca_file).
-- @treturn string|nil Chemin lisible, ou nil si aucun magasin n'est trouvé.
find_ca_file = (explicit) ->
  return explicit if ca_file_readable explicit
  env = os.getenv "SSL_CERT_FILE"
  return env if ca_file_readable env
  for path in *CA_FILE_CANDIDATES
    return path if ca_file_readable path
  nil

--- Vérifie que la libwolfssl chargée peut vérifier certificat ET nom d'hôte.
-- Exige les symboles de chargement du magasin, de SNI et de contrôle du nom ;
-- sans l'un d'eux (ou sans magasin de CA), un handshake « vérifié » ne
-- garantirait ni la chaîne ni l'identité du serveur.
-- @tparam table|nil opts {ca_file: string|nil}.
-- @treturn boolean Disponibilité de la vérification.
-- @treturn string|nil Raison de l'indisponibilité.
-- @treturn string|nil Chemin du magasin de CA retenu.
verification_available = (opts={}) ->
  missing = {}
  for name in *{"wolfSSL_CTX_load_verify_locations", "wolfSSL_UseSNI", "wolfSSL_check_domain_name"}
    missing[#missing + 1] = name unless symbol_available name
  unless #missing == 0
    return false, "symboles absents: #{table.concat missing, ", "}", nil
  ca = find_ca_file opts.ca_file
  unless ca
    return false, "aucun magasin de CA trouvé", nil
  true, nil, ca

--- Configure ALPN au niveau du contexte serveur.
-- @tparam table lib Bibliothèque FFI (libwolfssl ou stub de test).
-- @tparam cdata ctx Contexte WOLFSSL_CTX.
-- @tparam string|nil protocols Liste séparée par virgules (défaut http/1.1).
-- @treturn string|nil "ctx" si configuré, nil sinon.
alpn_configure_ctx = (lib, ctx, protocols) ->
  protocols or= DEFAULT_ALPN_PROTOCOLS
  return nil unless symbol_available "wolfSSL_CTX_UseALPN", lib
  ok, ret = pcall ->
    lib.wolfSSL_CTX_UseALPN ctx, ffi.cast("char*", protocols),
      #protocols, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH
  return "ctx" if ok and ret == 1
  nil

--- Annonce ALPN sur un objet SSL serveur (repli sans wolfSSL_CTX_UseALPN).
-- @tparam table lib Bibliothèque FFI (libwolfssl ou stub de test).
-- @tparam cdata ssl Objet WOLFSSL.
-- @tparam string|nil protocols Liste séparée par virgules (défaut http/1.1).
-- @treturn boolean true si l'annonce a été acceptée.
alpn_configure_ssl = (lib, ssl, protocols) ->
  protocols or= DEFAULT_ALPN_PROTOCOLS
  return false unless symbol_available "wolfSSL_UseALPN", lib
  ok, ret = pcall ->
    lib.wolfSSL_UseALPN ssl, ffi.cast("char*", protocols),
      #protocols, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH
  ok and ret == 1

-- Create server context (compatible with luasec API)
newcontext = (opts = {}) ->
  -- Extract certificate and key from opts
  -- opts can be: {certificate: "path", key: "path"} (luasec style)
  cert_file = opts.certificate or opts[1]
  key_file = opts.key or opts[2]

  if not cert_file or not key_file
    error "newcontext requires {certificate: 'path', key: 'path'}"

  method = libwolfssl.wolfTLS_server_method!
  if method == nil
    error "wolfTLS_server_method() failed"

  ctx = libwolfssl.wolfSSL_CTX_new(method)
  if ctx == nil
    error "wolfSSL_CTX_new() failed"

  ret = libwolfssl.wolfSSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM)
  if ret < 0
    libwolfssl.wolfSSL_CTX_free(ctx)
    error "wolfSSL_CTX_use_certificate_file() failed"

  ret = libwolfssl.wolfSSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM)
  if ret < 0
    libwolfssl.wolfSSL_CTX_free(ctx)
    error "wolfSSL_CTX_use_PrivateKey_file() failed"

  alpn_protocols = opts.alpn_protocols or DEFAULT_ALPN_PROTOCOLS
  alpn_mode = nil
  if _alpn_available != false
    alpn_mode = alpn_configure_ctx libwolfssl, ctx, alpn_protocols
    if alpn_mode == "ctx"
      _alpn_available = true
      log_debug -> { action: "ctx_use_alpn", protocols: alpn_protocols }
    elseif symbol_available "wolfSSL_UseALPN"
      -- OpenWrt (libwolfssl 5.8.4) n'expose pas wolfSSL_CTX_UseALPN mais
      -- wolfSSL_UseALPN : l'annonce se fera par objet SSL dans wrap().
      alpn_mode = "ssl"
      _alpn_available = true
      log_debug -> { action: "alpn_ssl_level", protocols: alpn_protocols }
    else
      _alpn_available = false
      log_debug -> { action: "alpn_unavailable" }
  else
    log_debug -> { action: "alpn_unavailable" }

  {
    :ctx
    closed: false
    :alpn_mode
    :alpn_protocols
    alpn_configured_protocols: if alpn_mode == "ctx" then alpn_protocols else nil
  }

--- Create a client TLS context (opt-in certificate verification via opts.verify_peer).
-- Quand `verify_peer` est vrai, charge le magasin de CA (`opts.ca_file` ou
-- détection système) et active SSL_VERIFY_PEER. Échoue si aucun magasin n'est
-- disponible : jamais de vérification silencieusement absente.
-- @tparam table opts {verify_peer: bool, ca_file: string|nil}
-- @treturn table ctx_obj compatible with wrap()
newclient_context = (opts={}) ->
  method = libwolfssl.wolfTLS_client_method!
  error "wolfTLS_client_method() failed" if method == nil
  ctx = libwolfssl.wolfSSL_CTX_new method
  error "wolfSSL_CTX_new() failed (client)" if ctx == nil
  ca_file = nil
  if opts.verify_peer
    ca_file = opts.ca_file or find_ca_file!
    unless ca_file
      libwolfssl.wolfSSL_CTX_free ctx
      error "no CA store available for peer verification"
    libwolfssl.wolfSSL_CTX_set_verify ctx, SSL_VERIFY_PEER, nil
    ret = libwolfssl.wolfSSL_CTX_load_verify_locations ctx, ca_file, nil
    if ret != 1
      libwolfssl.wolfSSL_CTX_free ctx
      error "wolfSSL_CTX_load_verify_locations() failed for #{ca_file} (ret=#{ret})"
  { :ctx, closed: false, verify_peer: opts.verify_peer == true, :ca_file }

-- Wrap raw socket with TLS
-- @tparam table raw_socket Socket (lib.socket).
-- @tparam table ctx_obj Contexte créé par newclient_context/newcontext.
-- @tparam table|nil opts {sni: string|nil, check_domain: string|nil}.
wrap = (raw_socket, ctx_obj, opts={}) ->
  log_debug -> { action: "wrap_start", fd: raw_socket.fd }

  ssl = libwolfssl.wolfSSL_new(ctx_obj.ctx)
  log_debug -> { action: "wolfssl_new" }
  if ssl == nil
    error "wolfSSL_new() failed"

  ret = libwolfssl.wolfSSL_set_fd(ssl, raw_socket.fd)
  log_debug -> { action: "wolfssl_set_fd", ret: ret }
  if ret < 0
    libwolfssl.wolfSSL_free(ssl)
    error "wolfSSL_set_fd() failed: ret="..ret

  -- ALPN serveur par objet SSL quand le contexte ne l'a pas configuré
  -- (OpenWrt : wolfSSL_CTX_UseALPN absent, wolfSSL_UseALPN présent). Jamais
  -- tenté sur un contexte client : seul newcontext renseigne alpn_mode.
  -- Les protocoles sont lus à chaque wrap : le worker DoH peut demander
  -- h2,http/1.1 sur un contexte créé avec le défaut http/1.1.
  alpn_protocols = ctx_obj.alpn_protocols or DEFAULT_ALPN_PROTOCOLS
  if ctx_obj.alpn_mode == "ssl"
    unless alpn_configure_ssl libwolfssl, ssl, alpn_protocols
      log_debug -> { action: "alpn_ssl_failed", protocols: alpn_protocols }
      _alpn_available = false
  elseif ctx_obj.alpn_mode == "ctx" and ctx_obj.alpn_configured_protocols != alpn_protocols
    unless alpn_configure_ctx libwolfssl, ctx_obj.ctx, alpn_protocols
      log_debug -> { action: "alpn_ctx_update_failed", protocols: alpn_protocols }
      _alpn_available = false
    else
      ctx_obj.alpn_configured_protocols = alpn_protocols

  -- SNI doit précéder le handshake (RFC 6066). Ne pas envoyer d'IP littérale.
  if opts.sni and #opts.sni > 0
    ret_sni = libwolfssl.wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, opts.sni, #opts.sni)
    if ret_sni != 1
      libwolfssl.wolfSSL_free(ssl)
      error "wolfSSL_UseSNI() failed: ret=#{ret_sni}"

  -- Contrôle du nom d'hôte (SAN/CN) pendant le handshake, en plus de la chaîne.
  if opts.check_domain and #opts.check_domain > 0
    ret_dom = libwolfssl.wolfSSL_check_domain_name(ssl, opts.check_domain)
    if ret_dom != 1
      libwolfssl.wolfSSL_free(ssl)
      error "wolfSSL_check_domain_name() failed: ret=#{ret_dom}"

  wrapped = {
    :ssl
    :raw_socket
    handshake_done: false
    closed: false
  }
  setmetatable(wrapped, ssl_mt)
  log_debug -> { action: "wrap_complete" }
  wrapped

-- Do handshake
ssl_mt.__index.dohandshake = =>
  log_debug -> { action: "dohandshake_start", closed: @closed, handshake_done: @handshake_done }

  if @closed
    error "SSL connection is closed"

  if @handshake_done
    log_debug -> { action: "handshake_already_done" }
    return true

  log_debug -> { action: "wolfssl_accept_call" }
  ret = libwolfssl.wolfSSL_accept(@ssl)
  log_debug -> { action: "wolfssl_accept_returned", ret: ret }

  if ret > 0
    @handshake_done = true
    log_debug -> { action: "handshake_success" }
    return true

  err = libwolfssl.wolfSSL_get_error(@ssl, ret)
  log_debug -> { action: "wolfssl_get_error", err: err }

  if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE
    log_debug -> { action: "handshake_want_read_write" }
    return false

  ssl_errors = get_ssl_errors!
  if err == -308 or err == -313 or err == 6 or (ssl_errors and (ssl_errors\find("error state on socket", 1, true) or ssl_errors\find("received alert fatal error", 1, true) or ssl_errors\find("peer sent close notify alert", 1, true)))
    log_debug -> { action: "handshake_peer_closed", err: err, ssl_err: ssl_errors }
    return false, "peer_closed"

  -- Toute autre erreur WolfSSL (parse error, cipher mismatch, HTTP brut sur port TLS…)
  -- est une erreur côté client — on la remonte sans exception pour éviter log ERROR.
  log_debug -> { action: "handshake_tls_error", err: err, ssl_err: ssl_errors or "" }
  return false, "tls_error"

-- TLS handshake (client side — wolfSSL_connect au lieu de wolfSSL_accept)
ssl_mt.__index.doconnect = =>
  error "SSL connection is closed" if @closed
  return true if @handshake_done
  ret = libwolfssl.wolfSSL_connect @ssl
  if ret > 0
    @handshake_done = true
    return true
  err = libwolfssl.wolfSSL_get_error @ssl, ret
  return false if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE
  ssl_errors = get_ssl_errors!
  false, "tls_connect_error: err=#{err} #{ssl_errors}"

ssl_mt.__index.selected_alpn = =>
  return nil if _alpn_available == false
  proto_ptr = ffi.new "char*[1]"
  proto_len = ffi.new "unsigned short[1]"
  ok, ret = pcall -> libwolfssl.wolfSSL_ALPN_GetProtocol @ssl, proto_ptr, proto_len
  unless ok and ret == 0 and proto_ptr[0] != nil and proto_len[0] > 0
    return nil
  ffi.string proto_ptr[0], proto_len[0]

-- Send
ssl_mt.__index.send = (data) =>
  if @closed
    error "SSL connection is closed"

  if not @handshake_done
    return nil

  n = libwolfssl.wolfSSL_write(@ssl, data, #data)
  if n > 0
    return n

  err = libwolfssl.wolfSSL_get_error(@ssl, n)
  if err == SSL_ERROR_WANT_WRITE or err == SSL_ERROR_WANT_READ
    return nil

  ssl_errors = get_ssl_errors!
  log_debug -> { action: "wolfssl_write_error", ret: n, err: err, ssl_err: ssl_errors }
  error "wolfSSL_write() failed (ret: #{n}, error code: #{err}, ssl_err: #{ssl_errors})"

-- Receive
ssl_mt.__index.receive = (mode = 4096) =>
  if @closed
    error "SSL connection is closed"

  if not @handshake_done
    error "TLS handshake not complete"

  -- Handle both "*l" (line) and numeric (size) modes
  if mode == "*l"
    -- Read line-by-line (HTTP request format)
    log_debug -> { action: "receive_line_mode" }
    max_line = 4096
    line_buf = ffi.new("uint8_t[?]", max_line)
    line_len = 0

    while line_len < max_line - 1
      n = libwolfssl.wolfSSL_read(@ssl, ffi.cast("uint8_t*", ffi.cast("void*", line_buf)) + line_len, 1)
      log_debug -> { action: "read_byte", ret: n }

      if n <= 0
        if line_len > 0
          log_debug -> { action: "partial_line", len: line_len }
          return ffi.string(line_buf, line_len)
        err = libwolfssl.wolfSSL_get_error(@ssl, n)
        errno = get_errno!
        log_debug -> { action: "wolfssl_read_error", ret: n, err: err, errno: errno }
        if n == 0
          return nil, "eof_from_peer"
        if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE
          return nil, "want_read_write"
        ssl_errors = get_ssl_errors!
        return nil, "wolfSSL_read() failed (ret: #{n}, error code: #{err}, errno: #{errno}, ssl_err: #{ssl_errors})"

      -- Check for newline
      byte_val = line_buf[line_len]
      if byte_val == 10  -- '\n'
        log_debug -> { action: "found_newline", pos: line_len }
        -- Strip trailing \r if present
        if line_len > 0 and line_buf[line_len - 1] == 13
          log_debug -> { action: "strip_cr" }
          return ffi.string(line_buf, line_len - 1)
        return ffi.string(line_buf, line_len)

      line_len += 1

    error "Line too long"
  else
    -- Numeric size mode
    size = tonumber(mode) or 4096
    log_debug -> { action: "receive_bytes", size: size }

    buf = ffi.new("uint8_t[?]", size)
    n = libwolfssl.wolfSSL_read(@ssl, buf, size)
    log_debug -> { action: "wolfssl_read_returned", ret: n }

    if n > 0
      return ffi.string(buf, n)

    if n == 0
      log_debug -> { action: "eof_from_peer" }
      return nil, "eof_from_peer"

    err = libwolfssl.wolfSSL_get_error(@ssl, n)
    errno = get_errno!
    log_debug -> { action: "wolfssl_read_error_numeric", ret: n, err: err, errno: errno }
    if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE
      log_debug -> { action: "want_read_write" }
      return nil, "want_read_write"

    ssl_errors = get_ssl_errors!
    return nil, "wolfSSL_read() error (ret: #{n}, code: #{err}, errno: #{errno}, ssl_err: #{ssl_errors})"

-- Close
ssl_mt.__index.close = =>
  if not @closed
    -- Drain non-bloquant : vide le buffer de réception TCP pour éviter que
    -- Linux envoie RST à la fermeture quand des données non lues sont présentes
    -- (ex. frames HTTP/2 après un préambule PRI détecté).
    if @handshake_done
      @raw_socket\settimeout 0          -- non-bloquant
      drain_buf = ffi.new "uint8_t[?]", 4096
      for _ = 1, 16
        n = libwolfssl.wolfSSL_read @ssl, drain_buf, 4096
        break if n <= 0
      @raw_socket\settimeout nil        -- bloquant (restore)
    libwolfssl.wolfSSL_shutdown(@ssl)
    libwolfssl.wolfSSL_free(@ssl)
    @raw_socket\close()
    @closed = true
  true

free_context = (ctx_obj) ->
  if ctx_obj and ctx_obj.ctx
    libwolfssl.wolfSSL_CTX_free(ctx_obj.ctx)
  true

{
  :newcontext
  :newclient_context
  :wrap
  :free_context
  :find_ca_file
  :verification_available
  :symbol_available
  :alpn_configure_ctx
  :alpn_configure_ssl
  :ALPN_PROTOCOLS
  :DEFAULT_ALPN_PROTOCOLS
  :libwolfssl
  :SSL_ERROR_NONE
  :SSL_ERROR_WANT_READ
  :SSL_ERROR_WANT_WRITE
  :SSL_ERROR_SSL
}
