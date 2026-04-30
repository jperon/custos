local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local s2mac
s2mac = require("ipparse.l2.ethernet").s2mac
local AF_PACKET = 17
local SOCK_RAW = 3
local ETH_P_ALL = 0x0300
local open_socket
open_socket = function(ifname)
  local fd = libc.socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)
  if fd < 0 then
    return nil, "socket() failed on " .. tostring(ifname) .. ": errno " .. tostring(ffi.errno())
  end
  return fd, nil
end
local read_mac
read_mac = function(ifname)
  local fh = io.open("/sys/class/net/" .. tostring(ifname) .. "/address", "r")
  if not (fh) then
    return nil
  end
  local mac_str = fh:read("*a"):gsub("\n", "")
  fh:close()
  if not (mac_str and #mac_str > 0) then
    return nil
  end
  return s2mac(mac_str)
end
local send
send = function(fd, frame, ifindex)
  local sll = ffi.new("struct sockaddr_ll")
  ffi.fill(sll, ffi.sizeof(sll), 0)
  sll.sll_family = AF_PACKET
  sll.sll_protocol = ETH_P_ALL
  sll.sll_ifindex = ifindex
  local n = libc.sendto(fd, frame, #frame, 0, ffi.cast("const struct sockaddr*", sll), ffi.sizeof(sll))
  return n == #frame
end
return {
  open_socket = open_socket,
  read_mac = read_mac,
  send = send
}
