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
  int wolfSSL_CTX_UseALPN(WOLFSSL_CTX *ctx, char *protocol_name_list,
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
WOLFSSL_ALPN_CONTINUE_ON_MISMATCH = 0x01
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

  if _alpn_available != false
    alpn = string.char(2) .. "h2" .. string.char(8) .. "http/1.1"
    ok_alpn, ret_alpn = pcall -> libwolfssl.wolfSSL_CTX_UseALPN(ctx, ffi.cast("char*", alpn), #alpn, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH)
    _alpn_available = ok_alpn
    if ok_alpn
      log_debug { action: "ctx_use_alpn", ret: ret_alpn or "nil", protocols: "h2,http/1.1" }
    else
      log_debug { action: "alpn_unavailable" }
  else
    log_debug { action: "alpn_unavailable" }

  {
    :ctx
    closed: false
  }

-- Wrap raw socket with TLS
wrap = (raw_socket, ctx_obj) ->
  log_debug { action: "wrap_start", fd: raw_socket.fd }

  ssl = libwolfssl.wolfSSL_new(ctx_obj.ctx)
  log_debug { action: "wolfssl_new" }
  if ssl == nil
    error "wolfSSL_new() failed"

  ret = libwolfssl.wolfSSL_set_fd(ssl, raw_socket.fd)
  log_debug { action: "wolfssl_set_fd", ret: ret }
  if ret < 0
    libwolfssl.wolfSSL_free(ssl)
    error "wolfSSL_set_fd() failed: ret="..ret

  wrapped = {
    :ssl
    :raw_socket
    handshake_done: false
    closed: false
  }
  setmetatable(wrapped, ssl_mt)
  log_debug { action: "wrap_complete" }
  wrapped

-- Do handshake
ssl_mt.__index.dohandshake = =>
  log_debug { action: "dohandshake_start", closed: @closed, handshake_done: @handshake_done }

  if @closed
    error "SSL connection is closed"

  if @handshake_done
    log_debug { action: "handshake_already_done" }
    return true

  log_debug { action: "wolfssl_accept_call" }
  ret = libwolfssl.wolfSSL_accept(@ssl)
  log_debug { action: "wolfssl_accept_returned", ret: ret }

  if ret > 0
    @handshake_done = true
    log_debug { action: "handshake_success" }
    return true

  err = libwolfssl.wolfSSL_get_error(@ssl, ret)
  log_debug { action: "wolfssl_get_error", err: err }

  if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE
    log_debug { action: "handshake_want_read_write" }
    return false

  if err == SSL_ERROR_SSL
    ssl_errors = get_ssl_errors!
    log_debug { action: "handshake_ssl_error", ssl_err: ssl_errors }
    error "TLS error during handshake: #{ssl_errors}"

  -- Unexpected error code
  ssl_errors = get_ssl_errors!
  log_debug { action: "handshake_unexpected_error", err: err, ssl_err: ssl_errors }
  error "Unexpected error #{err}: #{ssl_errors}"

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

  error "wolfSSL_write() error"

-- Receive
ssl_mt.__index.receive = (mode = 4096) =>
  if @closed
    error "SSL connection is closed"

  if not @handshake_done
    error "TLS handshake not complete"

  -- Handle both "*l" (line) and numeric (size) modes
  if mode == "*l"
    -- Read line-by-line (HTTP request format)
    log_debug { action: "receive_line_mode" }
    max_line = 4096
    line_buf = ffi.new("uint8_t[?]", max_line)
    line_len = 0

    while line_len < max_line - 1
      n = libwolfssl.wolfSSL_read(@ssl, ffi.cast("uint8_t*", ffi.cast("void*", line_buf)) + line_len, 1)
      log_debug { action: "read_byte", ret: n }

      if n <= 0
        if line_len > 0
          log_debug { action: "partial_line", len: line_len }
          return ffi.string(line_buf, line_len)
        err = libwolfssl.wolfSSL_get_error(@ssl, n)
        errno = get_errno!
        log_debug { action: "wolfssl_read_error", ret: n, err: err, errno: errno }
        if n == 0
          return nil, "eof_from_peer"
        if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE
          return nil, "want_read_write"
        ssl_errors = get_ssl_errors!
        return nil, "wolfSSL_read() failed (ret: #{n}, error code: #{err}, errno: #{errno}, ssl_err: #{ssl_errors})"

      -- Check for newline
      byte_val = line_buf[line_len]
      if byte_val == 10  -- '\n'
        log_debug { action: "found_newline", pos: line_len }
        -- Strip trailing \r if present
        if line_len > 0 and line_buf[line_len - 1] == 13
          log_debug { action: "strip_cr" }
          return ffi.string(line_buf, line_len - 1)
        return ffi.string(line_buf, line_len)

      line_len += 1

    error "Line too long"
  else
    -- Numeric size mode
    size = tonumber(mode) or 4096
    log_debug { action: "receive_bytes", size: size }

    buf = ffi.new("uint8_t[?]", size)
    n = libwolfssl.wolfSSL_read(@ssl, buf, size)
    log_debug { action: "wolfssl_read_returned", ret: n }

    if n > 0
      return ffi.string(buf, n)

    if n == 0
      log_debug { action: "eof_from_peer" }
      return nil, "eof_from_peer"

    err = libwolfssl.wolfSSL_get_error(@ssl, n)
    errno = get_errno!
    log_debug { action: "wolfssl_read_error_numeric", ret: n, err: err, errno: errno }
    if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE
      log_debug { action: "want_read_write" }
      return nil, "want_read_write"

    ssl_errors = get_ssl_errors!
    return nil, "wolfSSL_read() error (ret: #{n}, code: #{err}, errno: #{errno}, ssl_err: #{ssl_errors})"

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
