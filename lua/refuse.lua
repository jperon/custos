local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local AF_INET, AF_INET6
do
  local _obj_0 = require("config")
  AF_INET, AF_INET6 = _obj_0.AF_INET, _obj_0.AF_INET6
end
local log_warn, log_info
do
  local _obj_0 = require("log")
  log_warn, log_info = _obj_0.log_warn, _obj_0.log_info
end
local SOCK_DGRAM = 2
local SOL_SOCKET = 1
local SO_REUSEADDR = 2
local SO_REUSEPORT = 15
local sock4 = -1
local sock6 = -1
local open_udp53
open_udp53 = function(af)
  local fd = libc.socket(af, SOCK_DGRAM, 0)
  if fd < 0 then
    return -1, "socket() echec"
  end
  local one = ffi.new("int[1]", 1)
  libc.setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, one, ffi.sizeof("int"))
  libc.setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, one, ffi.sizeof("int"))
  local rc
  if af == AF_INET then
    local addr = ffi.new("struct sockaddr_in")
    addr.sin_family = AF_INET
    addr.sin_port = libc.htons(53)
    rc = libc.bind(fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof("struct sockaddr_in"))
  else
    local addr = ffi.new("struct sockaddr_in6")
    addr.sin6_family = AF_INET6
    addr.sin6_port = libc.htons(53)
    rc = libc.bind(fd, ffi.cast("struct sockaddr*", addr), ffi.sizeof("struct sockaddr_in6"))
  end
  if rc < 0 then
    libc.close(fd)
    return -1, "bind() echec (af=" .. tostring(af) .. ")"
  end
  return fd, nil
end
local init
init = function()
  local fd4, err4 = open_udp53(AF_INET)
  if fd4 < 0 then
    log_warn({
      action = "refuse_init_fail",
      af = "ipv4",
      err = tostring(err4)
    })
  else
    sock4 = fd4
    log_info({
      action = "refuse_ready",
      af = "ipv4"
    })
  end
  local fd6, err6 = open_udp53(AF_INET6)
  if fd6 < 0 then
    return log_warn({
      action = "refuse_init_fail",
      af = "ipv6",
      err = tostring(err6)
    })
  else
    sock6 = fd6
    return log_info({
      action = "refuse_ready",
      af = "ipv6"
    })
  end
end
local send_refused
send_refused = function(dst_ip_raw, dst_port, dns_payload, af)
  if af == AF_INET then
    if sock4 < 0 then
      return 
    end
    local addr = ffi.new("struct sockaddr_in")
    addr.sin_family = AF_INET
    addr.sin_port = libc.htons(dst_port)
    ffi.copy(addr.sin_addr, dst_ip_raw, 4)
    return libc.sendto(sock4, dns_payload, #dns_payload, 0, ffi.cast("struct sockaddr*", addr), ffi.sizeof("struct sockaddr_in"))
  else
    if sock6 < 0 then
      return 
    end
    local addr = ffi.new("struct sockaddr_in6")
    addr.sin6_family = AF_INET6
    addr.sin6_port = libc.htons(dst_port)
    ffi.copy(addr.sin6_addr, dst_ip_raw, 16)
    return libc.sendto(sock6, dns_payload, #dns_payload, 0, ffi.cast("struct sockaddr*", addr), ffi.sizeof("struct sockaddr_in6"))
  end
end
return {
  init = init,
  send_refused = send_refused
}
