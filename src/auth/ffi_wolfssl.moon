-- src/auth/ffi_wolfssl.moon
-- FFI wrapper for WolfSSL (libwolfssl) TLS/SSL library.

ffi = require "ffi"

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
]]

-- Load library with multiple fallback strategies
libwolfssl = nil

-- Strategy 1: Try common names (works if ldconfig is configured)
for _, name in ipairs({"libwolfssl.so.5.8.4.e624513f", "libwolfssl.so.5", "libwolfssl.so.44", "wolfssl", "libwolfssl.so"})
  ok, lib = pcall(ffi.load, name)
  if ok
    libwolfssl = lib
    break

-- Strategy 2: If not found, scan /usr/lib for any libwolfssl*.so*
if not libwolfssl
  f = io.popen("find /usr/lib /lib -name 'libwolfssl*.so*' -type f 2>/dev/null | sort -V | tail -1")
  path = f\read("*a")\gsub("\n", "")
  f\close!
  
  if path and path ~= ""
    ok, lib = pcall(ffi.load, path)
    if ok
      libwolfssl = lib

if not libwolfssl
  error "libwolfssl not found in: /usr/lib, /lib, or standard search paths"

-- Error codes
SSL_ERROR_NONE = 0
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_ERROR_SSL = 1

-- File types
SSL_FILETYPE_PEM = 1
SSL_FILETYPE_ASN1 = 2

-- SSL object metatable
ssl_mt = {
  __index: {}
}

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
  
  {
    :ctx
    closed: false
  }

-- Wrap raw socket with TLS
wrap = (raw_socket, ctx_obj) ->
  ssl = libwolfssl.wolfSSL_new(ctx_obj.ctx)
  if ssl == nil
    error "wolfSSL_new() failed"
  
  ret = libwolfssl.wolfSSL_set_fd(ssl, raw_socket.fd)
  if ret < 0
    libwolfssl.wolfSSL_free(ssl)
    error "wolfSSL_set_fd() failed"
  
  wrapped = {
    :ssl
    :raw_socket
    handshake_done: false
    closed: false
  }
  setmetatable(wrapped, ssl_mt)
  wrapped

-- Do handshake
ssl_mt.__index.dohandshake = =>
  if @closed
    error "SSL connection is closed"
  
  if @handshake_done
    return true
  
  ret = libwolfssl.wolfSSL_accept(@ssl)
  if ret > 0
    @handshake_done = true
    return true
  
  err = libwolfssl.wolfSSL_get_error(@ssl, ret)
  if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE
    return false
  
  if err == SSL_ERROR_SSL
    error "TLS error during handshake"
  
  error "Unexpected error: "..err

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
  
  error "wolfSSL_write() error"

-- Receive
ssl_mt.__index.receive = (size = 4096) =>
  if @closed
    error "SSL connection is closed"
  
  if not @handshake_done
    return nil
  
  buf = ffi.new("uint8_t[?]", size)
  n = libwolfssl.wolfSSL_read(@ssl, buf, size)
  
  if n > 0
    return ffi.string(buf, n)
  
  if n == 0
    return nil
  
  err = libwolfssl.wolfSSL_get_error(@ssl, n)
  if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE
    return nil
  
  error "wolfSSL_read() error"

-- Close
ssl_mt.__index.close = =>
  if not @closed
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
  :wrap
  :free_context
  :libwolfssl
  :SSL_ERROR_NONE
  :SSL_ERROR_WANT_READ
  :SSL_ERROR_WANT_WRITE
  :SSL_ERROR_SSL
}
