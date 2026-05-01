local ffi = require("ffi")
ffi.cdef([[  typedef struct WOLFSSL_CTX WOLFSSL_CTX;
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
]])
local libwolfssl = nil
for _, name in ipairs({
  "libwolfssl.so.5.8.4.e624513f",
  "libwolfssl.so.5",
  "libwolfssl.so.44",
  "wolfssl",
  "libwolfssl.so"
}) do
  local ok, lib = pcall(ffi.load, name)
  if ok then
    libwolfssl = lib
    break
  end
end
if not libwolfssl then
  local f = io.popen("find /usr/lib /lib -name 'libwolfssl*.so*' -type f 2>/dev/null | sort -V | tail -1")
  local path = f:read("*a"):gsub("\n", "")
  f:close()
  if path and path ~= "" then
    local ok, lib = pcall(ffi.load, path)
    if ok then
      libwolfssl = lib
    end
  end
end
if not libwolfssl then
  error("libwolfssl not found in: /usr/lib, /lib, or standard search paths")
end
local SSL_ERROR_NONE = 0
local SSL_ERROR_WANT_READ = 2
local SSL_ERROR_WANT_WRITE = 3
local SSL_ERROR_SSL = 1
local SSL_FILETYPE_PEM = 1
local SSL_FILETYPE_ASN1 = 2
local ssl_mt = {
  __index = { }
}
local newcontext
newcontext = function(opts)
  if opts == nil then
    opts = { }
  end
  local cert_file = opts.certificate or opts[1]
  local key_file = opts.key or opts[2]
  if not cert_file or not key_file then
    error("newcontext requires {certificate: 'path', key: 'path'}")
  end
  local method = libwolfssl.wolfTLS_server_method()
  if method == nil then
    error("wolfTLS_server_method() failed")
  end
  local ctx = libwolfssl.wolfSSL_CTX_new(method)
  if ctx == nil then
    error("wolfSSL_CTX_new() failed")
  end
  local ret = libwolfssl.wolfSSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM)
  if ret < 0 then
    libwolfssl.wolfSSL_CTX_free(ctx)
    error("wolfSSL_CTX_use_certificate_file() failed")
  end
  ret = libwolfssl.wolfSSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM)
  if ret < 0 then
    libwolfssl.wolfSSL_CTX_free(ctx)
    error("wolfSSL_CTX_use_PrivateKey_file() failed")
  end
  return {
    ctx = ctx,
    closed = false
  }
end
local wrap
wrap = function(raw_socket, ctx_obj)
  print("[DEBUG-WOLFSSL-WRAP] Starting wrap. socket.fd=" .. raw_socket.fd .. ", ctx_obj.ctx=" .. tostring(ctx_obj.ctx))
  local ssl = libwolfssl.wolfSSL_new(ctx_obj.ctx)
  print("[DEBUG-WOLFSSL-WRAP] wolfSSL_new() returned: " .. tostring(ssl))
  if ssl == nil then
    error("wolfSSL_new() failed")
  end
  local ret = libwolfssl.wolfSSL_set_fd(ssl, raw_socket.fd)
  print("[DEBUG-WOLFSSL-WRAP] wolfSSL_set_fd(ssl=" .. tostring(ssl) .. ", fd=" .. raw_socket.fd .. ") returned: " .. ret)
  if ret < 0 then
    libwolfssl.wolfSSL_free(ssl)
    error("wolfSSL_set_fd() failed: ret=" .. ret)
  end
  local wrapped = {
    ssl = ssl,
    raw_socket = raw_socket,
    handshake_done = false,
    closed = false
  }
  setmetatable(wrapped, ssl_mt)
  print("[DEBUG-WOLFSSL-WRAP] Wrap complete. TLS connection object created.")
  return wrapped
end
ssl_mt.__index.dohandshake = function(self)
  print("[DEBUG-WOLFSSL-HS] Starting handshake. closed=" .. tostring(self.closed) .. ", handshake_done=" .. tostring(self.handshake_done))
  if self.closed then
    error("SSL connection is closed")
  end
  if self.handshake_done then
    print("[DEBUG-WOLFSSL-HS] Handshake already done, returning true")
    return true
  end
  print("[DEBUG-WOLFSSL-HS] Calling wolfSSL_accept()")
  local ret = libwolfssl.wolfSSL_accept(self.ssl)
  print("[DEBUG-WOLFSSL-HS] wolfSSL_accept() returned: " .. ret)
  if ret > 0 then
    self.handshake_done = true
    print("[DEBUG-WOLFSSL-HS] Handshake SUCCESS")
    return true
  end
  local err = libwolfssl.wolfSSL_get_error(self.ssl, ret)
  print("[DEBUG-WOLFSSL-HS] wolfSSL_get_error() returned: " .. err .. " (WANT_READ=2, WANT_WRITE=3, SSL_ERROR_SSL=1)")
  if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE then
    print("[DEBUG-WOLFSSL-HS] Handshake needs more data (WANT_READ/WANT_WRITE)")
    return false
  end
  if err == SSL_ERROR_SSL then
    print("[DEBUG-WOLFSSL-HS] TLS error during handshake")
    error("TLS error during handshake")
  end
  print("[DEBUG-WOLFSSL-HS] Unexpected error code: " .. err)
  return error("Unexpected error: " .. err)
end
ssl_mt.__index.send = function(self, data)
  if self.closed then
    error("SSL connection is closed")
  end
  if not self.handshake_done then
    return nil
  end
  local n = libwolfssl.wolfSSL_write(self.ssl, data, #data)
  if n > 0 then
    return n
  end
  local err = libwolfssl.wolfSSL_get_error(self.ssl, n)
  if err == SSL_ERROR_WANT_WRITE or err == SSL_ERROR_WANT_READ then
    return nil
  end
  return error("wolfSSL_write() error")
end
ssl_mt.__index.receive = function(self, mode)
  if mode == nil then
    mode = 4096
  end
  if self.closed then
    error("SSL connection is closed")
  end
  if not self.handshake_done then
    error("TLS handshake not complete")
  end
  if mode == "*l" then
    print("[DEBUG-WOLFSSL-RECV] receive('*l') called, reading line")
    local max_line = 4096
    local line_buf = ffi.new("uint8_t[?]", max_line)
    local line_len = 0
    while line_len < max_line - 1 do
      local n = libwolfssl.wolfSSL_read(self.ssl, ffi.cast("uint8_t*", ffi.cast("void*", line_buf)) + line_len, 1)
      print("[DEBUG-WOLFSSL-RECV] Read 1 byte, n=" .. n)
      if n <= 0 then
        if line_len > 0 then
          print("[DEBUG-WOLFSSL-RECV] Returning partial line of " .. line_len .. " bytes")
          return ffi.string(line_buf, line_len)
        end
        local err = libwolfssl.wolfSSL_get_error(self.ssl, n)
        if err == SSL_ERROR_WANT_READ then
          return nil
        end
        error("wolfSSL_read() failed")
      end
      local byte_val = line_buf[line_len]
      if byte_val == 10 then
        print("[DEBUG-WOLFSSL-RECV] Found newline at position " .. line_len)
        if line_len > 0 and line_buf[line_len - 1] == 13 then
          print("[DEBUG-WOLFSSL-RECV] Stripping trailing CR")
          return ffi.string(line_buf, line_len - 1)
        end
        return ffi.string(line_buf, line_len)
      end
      line_len = line_len + 1
    end
    return error("Line too long")
  else
    local size = tonumber(mode) or 4096
    print("[DEBUG-WOLFSSL-RECV] receive(" .. size .. ") called, reading bytes")
    local buf = ffi.new("uint8_t[?]", size)
    local n = libwolfssl.wolfSSL_read(self.ssl, buf, size)
    print("[DEBUG-WOLFSSL-RECV] wolfSSL_read returned " .. n)
    if n > 0 then
      return ffi.string(buf, n)
    end
    if n == 0 then
      print("[DEBUG-WOLFSSL-RECV] EOF from peer")
      return nil
    end
    local err = libwolfssl.wolfSSL_get_error(self.ssl, n)
    if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE then
      print("[DEBUG-WOLFSSL-RECV] WANT_READ/WRITE, returning nil")
      return nil
    end
    return error("wolfSSL_read() error")
  end
end
ssl_mt.__index.close = function(self)
  if not self.closed then
    libwolfssl.wolfSSL_shutdown(self.ssl)
    libwolfssl.wolfSSL_free(self.ssl)
    self.raw_socket:close()
    self.closed = true
  end
  return true
end
local free_context
free_context = function(ctx_obj)
  if ctx_obj and ctx_obj.ctx then
    libwolfssl.wolfSSL_CTX_free(ctx_obj.ctx)
  end
  return true
end
return {
  newcontext = newcontext,
  wrap = wrap,
  free_context = free_context,
  libwolfssl = libwolfssl,
  SSL_ERROR_NONE = SSL_ERROR_NONE,
  SSL_ERROR_WANT_READ = SSL_ERROR_WANT_READ,
  SSL_ERROR_WANT_WRITE = SSL_ERROR_WANT_WRITE,
  SSL_ERROR_SSL = SSL_ERROR_SSL
}
