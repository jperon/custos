local ffi, libc, SO_TIMESTAMP, SO_TIMESTAMP_NEW, SOL_SOCKET, SOL_SOCKET_MIPS
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, SO_TIMESTAMP, SO_TIMESTAMP_NEW, SOL_SOCKET, SOL_SOCKET_MIPS = _obj_0.ffi, _obj_0.libc, _obj_0.SO_TIMESTAMP, _obj_0.SO_TIMESTAMP_NEW, _obj_0.SOL_SOCKET, _obj_0.SOL_SOCKET_MIPS
end
local log_warn
log_warn = require("log").log_warn
local AF_INET = 2
local SOCK_DGRAM = 2
local _fd = nil
local open_socket
open_socket = function(c)
  local fd = c.socket(AF_INET, SOCK_DGRAM, 0)
  if not (fd and fd >= 0) then
    local errno = tonumber(c.__errno_location()[0])
    log_warn(function()
      return {
        action = "netstamp_enable_failed",
        stage = "socket",
        errno = errno
      }
    end)
    return nil
  end
  local one = ffi.new("int[1]", 1)
  local optlen = ffi.sizeof("int")
  local last_errno = 0
  local _list_0 = {
    SOL_SOCKET,
    SOL_SOCKET_MIPS
  }
  for _index_0 = 1, #_list_0 do
    local sol = _list_0[_index_0]
    local _list_1 = {
      SO_TIMESTAMP,
      SO_TIMESTAMP_NEW
    }
    for _index_1 = 1, #_list_1 do
      local ts = _list_1[_index_1]
      local rc = c.setsockopt(fd, sol, ts, one, optlen)
      if rc == 0 then
        return fd
      end
      last_errno = tonumber(c.__errno_location()[0])
    end
  end
  c.close(fd)
  log_warn(function()
    return {
      action = "netstamp_enable_failed",
      stage = "setsockopt",
      errno = last_errno
    }
  end)
  return nil
end
local enable
enable = function()
  _fd = open_socket(libc)
  return _fd
end
local get_fd
get_fd = function()
  return _fd
end
return {
  enable = enable,
  get_fd = get_fd,
  open_socket = open_socket,
  AF_INET = AF_INET,
  SOCK_DGRAM = SOCK_DGRAM,
  SO_TIMESTAMP = SO_TIMESTAMP,
  SO_TIMESTAMP_NEW = SO_TIMESTAMP_NEW,
  SOL_SOCKET = SOL_SOCKET,
  SOL_SOCKET_MIPS = SOL_SOCKET_MIPS
}
