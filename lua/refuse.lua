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
local IPPROTO_IP = 0
local IPPROTO_IPV6 = 41
local IP_TRANSPARENT = 19
local IPV6_TRANSPARENT = 75
local admin_available = false
local init
init = function()
  local fd = libc.socket(AF_INET, SOCK_DGRAM, 0)
  if fd >= 0 then
    local one = ffi.new("int[1]", 1)
    local rc = libc.setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, one, ffi.sizeof("int"))
    libc.close(fd)
    if rc == 0 then
      admin_available = true
      return log_info({
        action = "refuse_ready",
        mode = "ip_transparent"
      })
    else
      return log_warn({
        action = "refuse_init_fail",
        err = "IP_TRANSPARENT non disponible (CAP_NET_ADMIN requis)"
      })
    end
  else
    return log_warn({
      action = "refuse_init_fail",
      err = "socket() echec"
    })
  end
end
local send_refused
send_refused = function(dst_ip_raw, dst_port, dns_payload, af, src_ip_raw)
  if not (admin_available) then
    return 
  end
  local fd = libc.socket(af, SOCK_DGRAM, 0)
  if fd < 0 then
    return 
  end
  local one = ffi.new("int[1]", 1)
  libc.setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, one, ffi.sizeof("int"))
  libc.setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, one, ffi.sizeof("int"))
  if af == AF_INET then
    libc.setsockopt(fd, IPPROTO_IP, IP_TRANSPARENT, one, ffi.sizeof("int"))
    local src = ffi.new("struct sockaddr_in")
    src.sin_family = AF_INET
    src.sin_port = libc.htons(53)
    ffi.copy(src.sin_addr, src_ip_raw, 4)
    local rc = libc.bind(fd, ffi.cast("struct sockaddr*", src), ffi.sizeof("struct sockaddr_in"))
    if rc < 0 then
      libc.close(fd)
      log_warn({
        action = "refuse_bind_fail",
        af = "ipv4",
        err = ffi.errno()
      })
      return 
    end
    local dst = ffi.new("struct sockaddr_in")
    dst.sin_family = AF_INET
    dst.sin_port = libc.htons(dst_port)
    ffi.copy(dst.sin_addr, dst_ip_raw, 4)
    rc = libc.sendto(fd, dns_payload, #dns_payload, 0, ffi.cast("struct sockaddr*", dst), ffi.sizeof("struct sockaddr_in"))
    if rc < 0 then
      log_warn({
        action = "sendto_failed",
        af = "ipv4",
        err = ffi.errno()
      })
    end
  else
    libc.setsockopt(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, one, ffi.sizeof("int"))
    local src = ffi.new("struct sockaddr_in6")
    src.sin6_family = AF_INET6
    src.sin6_port = libc.htons(53)
    ffi.copy(src.sin6_addr, src_ip_raw, 16)
    local rc = libc.bind(fd, ffi.cast("struct sockaddr*", src), ffi.sizeof("struct sockaddr_in6"))
    if rc < 0 then
      libc.close(fd)
      log_warn({
        action = "refuse_bind_fail",
        af = "ipv6",
        err = ffi.errno()
      })
      return 
    end
    local dst = ffi.new("struct sockaddr_in6")
    dst.sin6_family = AF_INET6
    dst.sin6_port = libc.htons(dst_port)
    ffi.copy(dst.sin6_addr, dst_ip_raw, 16)
    rc = libc.sendto(fd, dns_payload, #dns_payload, 0, ffi.cast("struct sockaddr*", dst), ffi.sizeof("struct sockaddr_in6"))
    if rc < 0 then
      log_warn({
        action = "sendto_failed",
        af = "ipv6",
        err = ffi.errno()
      })
    end
  end
  return libc.close(fd)
end
return {
  init = init,
  send_refused = send_refused
}
