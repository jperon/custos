local ffi = require("ffi")
local log_info, log_warn, log_debug
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug
end
local SOL_SOCKET = 1
local SO_RCVBUF = 8
local SO_RCVBUFFORCE = 33
local DEFAULT_RCVBUF = 4 * 1024 * 1024
local LOWMEM_RCVBUF = 512 * 1024
local resolve_requested
resolve_requested = function(configured, is_lowmem)
  local v = tonumber(configured)
  if v and v > 0 then
    return v
  end
  if is_lowmem then
    return LOWMEM_RCVBUF
  else
    return DEFAULT_RCVBUF
  end
end
local socket_api_available
socket_api_available = function(libc)
  if not (libc) then
    return false
  end
  local _list_0 = {
    "setsockopt",
    "getsockopt"
  }
  for _index_0 = 1, #_list_0 do
    local name = _list_0[_index_0]
    local ok, fn = pcall(function()
      return libc[name]
    end)
    if not (ok and fn) then
      return false
    end
  end
  return pcall(function()
    return ffi.sizeof("socklen_t")
  end) and true or false
end
local read_back
read_back = function(libc, fd)
  local val = ffi.new("int[1]", 0)
  local len = ffi.new("socklen_t[1]", ffi.sizeof("int"))
  local rc = libc.getsockopt(fd, SOL_SOCKET, SO_RCVBUF, val, len)
  if not (rc == 0) then
    return nil
  end
  return math.floor(tonumber(val[0]) / 2)
end
local apply_rcvbuf
apply_rcvbuf = function(libc, fd, requested)
  if not (socket_api_available(libc)) then
    return nil
  end
  local val = ffi.new("int[1]", requested)
  local rc = libc.setsockopt(fd, SOL_SOCKET, SO_RCVBUF, val, ffi.sizeof("int"))
  if not (rc == 0) then
    return {
      requested = requested,
      obtained = nil,
      forced = false,
      error = tonumber(libc.__errno_location()[0])
    }
  end
  local res = {
    requested = requested,
    obtained = read_back(libc, fd),
    forced = false,
    error = nil
  }
  if res.obtained and res.obtained < requested then
    local rc_force = libc.setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, val, ffi.sizeof("int"))
    if rc_force == 0 then
      local effective = read_back(libc, fd)
      if effective and effective >= requested then
        res.obtained = effective
        res.forced = true
      end
    end
  end
  return res
end
local configure
configure = function(libc, fd, queue_num, configured, is_lowmem)
  local requested = resolve_requested(configured, is_lowmem)
  local res = apply_rcvbuf(libc, fd, requested)
  if not (res) then
    log_debug(function()
      return {
        action = "queue_rcvbuf_unavailable",
        queue = queue_num
      }
    end)
    return nil
  end
  if res.obtained then
    log_info(function()
      return {
        action = "queue_rcvbuf",
        queue = queue_num,
        requested = res.requested,
        obtained = res.obtained,
        forced = res.forced
      }
    end)
    if res.obtained < res.requested then
      log_warn(function()
        return {
          action = "queue_rcvbuf_below_requested",
          queue = queue_num,
          requested = res.requested,
          obtained = res.obtained,
          forced = res.forced
        }
      end)
    end
  else
    log_warn(function()
      return {
        action = "queue_rcvbuf_failed",
        queue = queue_num,
        requested = res.requested,
        errno = res.error
      }
    end)
  end
  return res
end
return {
  SOL_SOCKET = SOL_SOCKET,
  SO_RCVBUF = SO_RCVBUF,
  SO_RCVBUFFORCE = SO_RCVBUFFORCE,
  DEFAULT_RCVBUF = DEFAULT_RCVBUF,
  LOWMEM_RCVBUF = LOWMEM_RCVBUF,
  resolve_requested = resolve_requested,
  socket_api_available = socket_api_available,
  read_back = read_back,
  apply_rcvbuf = apply_rcvbuf,
  configure = configure
}
