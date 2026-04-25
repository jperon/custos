local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local MAC_LEARNER_QUERY_SOCK
MAC_LEARNER_QUERY_SOCK = require("config").MAC_LEARNER_QUERY_SOCK
local log_warn
log_warn = require("log").log_warn
local AF_UNIX = 1
local SOCK_STREAM = 1
local get_mac
get_mac = function(ip_str)
  if not (ip_str and ip_str ~= "" and ip_str ~= "unknown") then
    return "unknown"
  end
  local sock = libc.socket(AF_UNIX, SOCK_STREAM, 0)
  if not (sock >= 0) then
    log_warn({
      action = "mac_ipc_socket_failed",
      errno = tonumber(ffi.C.__errno_location()[0])
    })
    return "unknown"
  end
  local addr = ffi.new("struct sockaddr_un")
  addr.sun_family = AF_UNIX
  ffi.copy(addr.sun_path, MAC_LEARNER_QUERY_SOCK)
  local addr_len = 2 + #MAC_LEARNER_QUERY_SOCK + 1
  if libc.connect(sock, ffi.cast("struct sockaddr*", addr), addr_len) ~= 0 then
    libc.close(sock)
    return "unknown"
  end
  local req = ip_str .. "\n"
  libc.send(sock, req, #req, 0)
  local buf = ffi.new("char[64]")
  local n = libc.recv(sock, buf, 63, 0)
  libc.close(sock)
  if n <= 0 then
    return "unknown"
  end
  local resp = ffi.string(buf, n)
  local mac = resp:match("^([0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f])")
  return mac or "unknown"
end
return {
  get_mac = get_mac
}
