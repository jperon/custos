local ffi
ffi = require("ffi_defs").ffi
local C, AF_INET, AF_INET6, SOCK_RAW, SOCK_DGRAM
do
  local _obj_0 = require("lib.socket")
  C, AF_INET, AF_INET6, SOCK_RAW, SOCK_DGRAM = _obj_0.C, _obj_0.AF_INET, _obj_0.AF_INET6, _obj_0.SOCK_RAW, _obj_0.SOCK_DGRAM
end
local s2ip
s2ip = require("ipparse.l3.ip").s2ip
local IPPROTO_UDP = 17
local IPPROTO_RAW = 255
local IPPROTO_IPV6 = 41
local IPV6_HDRINCL = 36
local open
open = function(version)
  if version == 6 then
    local fd = C.socket(AF_INET6, SOCK_RAW, IPPROTO_UDP)
    if fd < 0 then
      return nil, ffi.errno()
    end
    local one = ffi.new("int[1]", 1)
    C.setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL, one, ffi.sizeof("int"))
    return fd
  else
    local fd = C.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
    if fd < 0 then
      return nil, ffi.errno()
    end
    return fd
  end
end
local _dest_addr
_dest_addr = function(version, dst_raw)
  if version == 6 then
    local sa = ffi.new("struct sockaddr_in6")
    sa.sin6_family = AF_INET6
    ffi.copy(sa.sin6_addr, dst_raw, 16)
    return sa, ffi.sizeof("struct sockaddr_in6")
  else
    local sa = ffi.new("struct sockaddr_in")
    sa.sin_family = AF_INET
    ffi.copy(sa.sin_addr, dst_raw, 4)
    return sa, ffi.sizeof("struct sockaddr_in")
  end
end
local send
send = function(fd, version, pkt, dst_ip)
  if not (fd and pkt and dst_ip) then
    return false
  end
  local ok, dst_raw = pcall(s2ip, dst_ip)
  if not (ok and dst_raw) then
    return false
  end
  local sa, salen = _dest_addr(version, dst_raw)
  local n = C.sendto(fd, pkt, #pkt, 0, ffi.cast("const struct sockaddr*", sa), salen)
  return n == #pkt
end
local routable
routable = function(version, dst_ip)
  if not (dst_ip) then
    return false
  end
  local ok, dst_raw = pcall(s2ip, dst_ip)
  if not (ok and dst_raw) then
    return false
  end
  local af = version == 6 and AF_INET6 or AF_INET
  local fd = C.socket(af, SOCK_DGRAM, IPPROTO_UDP)
  if fd < 0 then
    return false
  end
  local sa, salen = _dest_addr(version, dst_raw)
  local rc = C.connect(fd, ffi.cast("const struct sockaddr*", sa), salen)
  C.close(fd)
  return rc == 0
end
return {
  open = open,
  send = send,
  routable = routable,
  IPPROTO_RAW = IPPROTO_RAW,
  IPPROTO_UDP = IPPROTO_UDP
}
