local ffi = require("ffi")
local log_debug
log_debug = require("log").log_debug
local get_errno
get_errno = require("lib.socket").get_errno
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
  int wolfSSL_CTX_UseALPN(WOLFSSL_CTX *ctx, char *protocol_name_list,
                          unsigned int protocol_name_listSz, unsigned char options);
  int wolfSSL_ALPN_GetProtocol(WOLFSSL *ssl, char **protocol_name, unsigned short *size);
  unsigned long wolfSSL_ERR_get_error(void);
  char* wolfSSL_ERR_reason_error_string(unsigned long err);
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
local WOLFSSL_ALPN_CONTINUE_ON_MISMATCH = 0x01
local _alpn_available = nil
local get_ssl_errors
get_ssl_errors = function()
  local errors = { }
  while true do
    local err = libwolfssl.wolfSSL_ERR_get_error()
    if err == 0 then
      break
    end
    local reason_ptr = libwolfssl.wolfSSL_ERR_reason_error_string(err)
    local reason
    if reason_ptr ~= nil then
      reason = ffi.string(reason_ptr)
    else
      reason = "unknown"
    end
    table.insert(errors, tostring(err) .. ":" .. tostring(reason))
  end
  return table.concat(errors, " | ")
end
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
  if _alpn_available ~= false then
    local alpn = string.char(2) .. "h2" .. string.char(8) .. "http/1.1"
    local ok_alpn, ret_alpn = pcall(function()
      return libwolfssl.wolfSSL_CTX_UseALPN(ctx, ffi.cast("char*", alpn), #alpn, WOLFSSL_ALPN_CONTINUE_ON_MISMATCH)
    end)
    _alpn_available = ok_alpn
    if ok_alpn then
      log_debug({
        action = "ctx_use_alpn",
        ret = ret_alpn or "nil",
        protocols = "h2,http/1.1"
      })
    else
      log_debug({
        action = "alpn_unavailable"
      })
    end
  else
    log_debug({
      action = "alpn_unavailable"
    })
  end
  return {
    ctx = ctx,
    closed = false
  }
end
local wrap
wrap = function(raw_socket, ctx_obj)
  log_debug({
    action = "wrap_start",
    fd = raw_socket.fd
  })
  local ssl = libwolfssl.wolfSSL_new(ctx_obj.ctx)
  log_debug({
    action = "wolfssl_new"
  })
  if ssl == nil then
    error("wolfSSL_new() failed")
  end
  local ret = libwolfssl.wolfSSL_set_fd(ssl, raw_socket.fd)
  log_debug({
    action = "wolfssl_set_fd",
    ret = ret
  })
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
  log_debug({
    action = "wrap_complete"
  })
  return wrapped
end
ssl_mt.__index.dohandshake = function(self)
  log_debug({
    action = "dohandshake_start",
    closed = self.closed,
    handshake_done = self.handshake_done
  })
  if self.closed then
    error("SSL connection is closed")
  end
  if self.handshake_done then
    log_debug({
      action = "handshake_already_done"
    })
    return true
  end
  log_debug({
    action = "wolfssl_accept_call"
  })
  local ret = libwolfssl.wolfSSL_accept(self.ssl)
  log_debug({
    action = "wolfssl_accept_returned",
    ret = ret
  })
  if ret > 0 then
    self.handshake_done = true
    log_debug({
      action = "handshake_success"
    })
    return true
  end
  local err = libwolfssl.wolfSSL_get_error(self.ssl, ret)
  log_debug({
    action = "wolfssl_get_error",
    err = err
  })
  if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE then
    log_debug({
      action = "handshake_want_read_write"
    })
    return false
  end
  if err == SSL_ERROR_SSL then
    local ssl_errors = get_ssl_errors()
    log_debug({
      action = "handshake_ssl_error",
      ssl_err = ssl_errors
    })
    error("TLS error during handshake: " .. tostring(ssl_errors))
  end
  local ssl_errors = get_ssl_errors()
  if err == -308 or (ssl_errors and ssl_errors:find("error state on socket", 1, true)) then
    log_debug({
      action = "handshake_peer_closed",
      err = err,
      ssl_err = ssl_errors
    })
    return false, "peer_closed"
  end
  log_debug({
    action = "handshake_unexpected_error",
    err = err,
    ssl_err = ssl_errors
  })
  return error("Unexpected error " .. tostring(err) .. ": " .. tostring(ssl_errors))
end
ssl_mt.__index.selected_alpn = function(self)
  if _alpn_available == false then
    return nil
  end
  local proto_ptr = ffi.new("char*[1]")
  local proto_len = ffi.new("unsigned short[1]")
  local ok, ret = pcall(function()
    return libwolfssl.wolfSSL_ALPN_GetProtocol(self.ssl, proto_ptr, proto_len)
  end)
  if not (ok and ret == 0 and proto_ptr[0] ~= nil and proto_len[0] > 0) then
    return nil
  end
  return ffi.string(proto_ptr[0], proto_len[0])
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
  local ssl_errors = get_ssl_errors()
  log_debug({
    action = "wolfssl_write_error",
    ret = n,
    err = err,
    ssl_err = ssl_errors
  })
  return error("wolfSSL_write() failed (ret: " .. tostring(n) .. ", error code: " .. tostring(err) .. ", ssl_err: " .. tostring(ssl_errors) .. ")")
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
    log_debug({
      action = "receive_line_mode"
    })
    local max_line = 4096
    local line_buf = ffi.new("uint8_t[?]", max_line)
    local line_len = 0
    while line_len < max_line - 1 do
      local n = libwolfssl.wolfSSL_read(self.ssl, ffi.cast("uint8_t*", ffi.cast("void*", line_buf)) + line_len, 1)
      log_debug({
        action = "read_byte",
        ret = n
      })
      if n <= 0 then
        if line_len > 0 then
          log_debug({
            action = "partial_line",
            len = line_len
          })
          return ffi.string(line_buf, line_len)
        end
        local err = libwolfssl.wolfSSL_get_error(self.ssl, n)
        local errno = get_errno()
        log_debug({
          action = "wolfssl_read_error",
          ret = n,
          err = err,
          errno = errno
        })
        if n == 0 then
          return nil, "eof_from_peer"
        end
        if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE then
          return nil, "want_read_write"
        end
        local ssl_errors = get_ssl_errors()
        return nil, "wolfSSL_read() failed (ret: " .. tostring(n) .. ", error code: " .. tostring(err) .. ", errno: " .. tostring(errno) .. ", ssl_err: " .. tostring(ssl_errors) .. ")"
      end
      local byte_val = line_buf[line_len]
      if byte_val == 10 then
        log_debug({
          action = "found_newline",
          pos = line_len
        })
        if line_len > 0 and line_buf[line_len - 1] == 13 then
          log_debug({
            action = "strip_cr"
          })
          return ffi.string(line_buf, line_len - 1)
        end
        return ffi.string(line_buf, line_len)
      end
      line_len = line_len + 1
    end
    return error("Line too long")
  else
    local size = tonumber(mode) or 4096
    log_debug({
      action = "receive_bytes",
      size = size
    })
    local buf = ffi.new("uint8_t[?]", size)
    local n = libwolfssl.wolfSSL_read(self.ssl, buf, size)
    log_debug({
      action = "wolfssl_read_returned",
      ret = n
    })
    if n > 0 then
      return ffi.string(buf, n)
    end
    if n == 0 then
      log_debug({
        action = "eof_from_peer"
      })
      return nil, "eof_from_peer"
    end
    local err = libwolfssl.wolfSSL_get_error(self.ssl, n)
    local errno = get_errno()
    log_debug({
      action = "wolfssl_read_error_numeric",
      ret = n,
      err = err,
      errno = errno
    })
    if err == SSL_ERROR_WANT_READ or err == SSL_ERROR_WANT_WRITE then
      log_debug({
        action = "want_read_write"
      })
      return nil, "want_read_write"
    end
    local ssl_errors = get_ssl_errors()
    return nil, "wolfSSL_read() error (ret: " .. tostring(n) .. ", code: " .. tostring(err) .. ", errno: " .. tostring(errno) .. ", ssl_err: " .. tostring(ssl_errors) .. ")"
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
