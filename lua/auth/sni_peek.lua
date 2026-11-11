local ffi = require("ffi")
local socket_select
socket_select = require("lib.socket").socket_select
local extract_sni
extract_sni = require("auth.sni_extractor").extract_sni
pcall(ffi.cdef, "int recv(int sockfd, void *buf, unsigned long len, int flags);")
local PEEK_FLAGS = 66
local TLS_RECORD_HEADER = 5
local PEEK_MAX_BYTES = 8192
local DEFAULT_TIMEOUT = 15
local record_target
record_target = function(data)
  if not (data and #data >= TLS_RECORD_HEADER) then
    return nil
  end
  local record_len = data:byte(4) * 256 + data:byte(5)
  if record_len <= 0 then
    return nil
  end
  return math.min(TLS_RECORD_HEADER + record_len, PEEK_MAX_BYTES)
end
local wait_readable
wait_readable = function(sock, timeout)
  local fds = {
    sock
  }
  local readable, _ = socket_select(fds, nil, timeout)
  return readable and #readable > 0
end
local peek_fd
peek_fd = function(fd, len)
  local buf = ffi.new("uint8_t[?]", len)
  local n = ffi.C.recv(fd, buf, len, PEEK_FLAGS)
  if n <= 0 then
    return nil
  end
  return ffi.string(buf, n)
end
local read_client_hello
read_client_hello = function(sock, opts)
  if opts == nil then
    opts = { }
  end
  if not (sock and type(sock.fd) == "number") then
    return nil
  end
  local now_fn = opts.now_fn or os.time
  local timeout = tonumber(opts.timeout) or DEFAULT_TIMEOUT
  if timeout <= 0 then
    timeout = DEFAULT_TIMEOUT
  end
  local deadline = opts.deadline or (now_fn() + timeout)
  local wait_fn = opts.wait_fn or wait_readable
  local peek_fn = opts.peek_fn or peek_fd
  local data = ""
  while true do
    local target
    if #data >= TLS_RECORD_HEADER then
      target = record_target(data)
    else
      target = TLS_RECORD_HEADER
    end
    if not (target) then
      break
    end
    if #data >= target then
      return data
    end
    local remaining = deadline - now_fn()
    if remaining <= 0 then
      break
    end
    if not (wait_fn(sock, remaining)) then
      break
    end
    local chunk = peek_fn(sock.fd, target)
    if not (chunk and #chunk > 0) then
      break
    end
    if #chunk <= #data then
      break
    end
    data = chunk
  end
  if #data == 0 then
    return nil
  end
  return data
end
local extract_client_sni
extract_client_sni = function(sock, opts)
  if opts == nil then
    opts = { }
  end
  local ok, sni = pcall(function()
    local data = read_client_hello(sock, opts)
    if data then
      return extract_sni(data)
    end
  end)
  if not (ok) then
    return nil
  end
  return sni or nil
end
return {
  read_client_hello = read_client_hello,
  extract_client_sni = extract_client_sni,
  record_target = record_target,
  PEEK_MAX_BYTES = PEEK_MAX_BYTES
}
