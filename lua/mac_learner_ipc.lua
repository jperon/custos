local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local config = require("config")
local log_warn
log_warn = require("log").log_warn
local learner_cfg = config.mac_learner or { }
local QUERY_SOCK = learner_cfg.query_sock or config.MAC_LEARNER_QUERY_SOCK or "/var/run/custos/mac_query.sock"
local AF_UNIX = 1
local AF_INET6 = 10
local SOCK_STREAM = 1
local bit = require("bit")
local mac2s
mac2s = require("packet_utils").mac2s
local mac_from_eui64
mac_from_eui64 = function(ip_str)
  if not (ip_str) then
    return nil
  end
  if not (ip_str:find(":", 1, true)) then
    return nil
  end
  local buf = ffi.new("uint8_t[16]")
  if libc.inet_pton(AF_INET6, ip_str, buf) ~= 1 then
    return nil
  end
  if not (buf[11] == 0xff and buf[12] == 0xfe) then
    return nil
  end
  local b0 = bit.bxor(buf[8], 0x02)
  return mac2s(string.char(b0, buf[9], buf[10], buf[13], buf[14], buf[15]))
end
local get_mac
get_mac = function(ip_str)
  if not (ip_str and ip_str ~= "" and ip_str ~= "unknown") then
    return "unknown"
  end
  local sock = libc.socket(AF_UNIX, SOCK_STREAM, 0)
  if not (sock >= 0) then
    log_warn(function()
      return {
        action = "mac_ipc_socket_failed",
        errno = tonumber(ffi.C.__errno_location()[0])
      }
    end)
    return mac_from_eui64(ip_str) or "unknown"
  end
  local addr = ffi.new("struct sockaddr_un")
  addr.sun_family = AF_UNIX
  ffi.copy(addr.sun_path, QUERY_SOCK)
  local addr_len = ffi.offsetof("struct sockaddr_un", "sun_path") + #QUERY_SOCK + 1
  if libc.connect(sock, ffi.cast("struct sockaddr*", addr), addr_len) ~= 0 then
    libc.close(sock)
    return mac_from_eui64(ip_str) or "unknown"
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
  if mac then
    return mac
  end
  mac = mac_from_eui64(ip_str)
  if mac then
    return mac
  end
  return "unknown"
end
local get_vlan
get_vlan = function(ip_str)
  if not (ip_str and ip_str ~= "" and ip_str ~= "unknown") then
    return nil
  end
  local sock = libc.socket(AF_UNIX, SOCK_STREAM, 0)
  if not (sock >= 0) then
    log_warn(function()
      return {
        action = "vlan_ipc_socket_failed",
        errno = tonumber(ffi.C.__errno_location()[0])
      }
    end)
    return nil
  end
  local addr = ffi.new("struct sockaddr_un")
  addr.sun_family = AF_UNIX
  ffi.copy(addr.sun_path, QUERY_SOCK)
  local addr_len = ffi.offsetof("struct sockaddr_un", "sun_path") + #QUERY_SOCK + 1
  if libc.connect(sock, ffi.cast("struct sockaddr*", addr), addr_len) ~= 0 then
    libc.close(sock)
    return nil
  end
  local req = "vlan:" .. ip_str .. "\n"
  libc.send(sock, req, #req, 0)
  local buf = ffi.new("char[64]")
  local n = libc.recv(sock, buf, 63, 0)
  libc.close(sock)
  if n <= 0 then
    return nil
  end
  local resp = ffi.string(buf, n)
  local id = resp:match("^(%d+)")
  if id then
    return tonumber(id)
  end
  return nil
end
return {
  get_mac = get_mac,
  get_vlan = get_vlan,
  mac_from_eui64 = mac_from_eui64
}
