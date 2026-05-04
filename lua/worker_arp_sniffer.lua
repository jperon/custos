local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local C, AF_PACKET, SOCK_RAW, AF_INET6
do
  local _obj_0 = require("lib.socket")
  C, AF_PACKET, SOCK_RAW, AF_INET6 = _obj_0.C, _obj_0.AF_PACKET, _obj_0.SOCK_RAW, _obj_0.AF_INET6
end
local log_info, log_warn, log_debug, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug, _obj_0.set_action_prefix
end
local POLLIN = 1
local ETH_P_ARP = C.htons(0x0806)
local ETH_P_IPV6 = C.htons(0x86DD)
local ICMPV6_PROTO = 58
local ICMPV6_TYPE_NS = 135
local ICMPV6_TYPE_NA = 136
local ARP_MIN_LEN = 42
local NDP_MIN_LEN = 56
local fmt_mac
fmt_mac = function(s, o)
  return string.format("%02x:%02x:%02x:%02x:%02x:%02x", s:byte(o), s:byte(o + 1), s:byte(o + 2), s:byte(o + 3), s:byte(o + 4), s:byte(o + 5))
end
local fmt_ipv6
fmt_ipv6 = function(s, o)
  local buf = ffi.new("uint8_t[16]")
  for i = 0, 15 do
    buf[i] = s:byte(o + i)
  end
  local ntop = ffi.new("char[46]")
  local rc = C.inet_ntop(AF_INET6, buf, ntop, 46)
  if rc == nil then
    return "?"
  end
  return ffi.string(ntop)
end
local build_learn_msg
build_learn_msg = function(raw, ip_off, ip_len, mac_off)
  local msg = ffi.new("uint8_t[22]")
  for i = 0, ip_len - 1 do
    msg[i] = raw:byte(ip_off + i)
  end
  for i = 0, 5 do
    msg[16 + i] = raw:byte(mac_off + i)
  end
  return msg
end
local write_learn
write_learn = function(learn_wfd, msg)
  local n = libc.write(learn_wfd, msg, 22)
  return n == 22
end
local open_socket
open_socket = function(eth_proto, ifindex)
  local fd = C.socket(AF_PACKET, SOCK_RAW, eth_proto)
  if fd < 0 then
    return nil
  end
  local sll = ffi.new("struct sockaddr_ll")
  ffi.fill(sll, ffi.sizeof(sll), 0)
  sll.sll_family = AF_PACKET
  sll.sll_protocol = eth_proto
  sll.sll_ifindex = ifindex
  if C.bind(fd, ffi.cast("struct sockaddr*", sll), ffi.sizeof(sll)) ~= 0 then
    libc.close(fd)
    return nil
  end
  return fd
end
local process_arp
process_arp = function(raw, len, learn_wfd)
  if len < ARP_MIN_LEN then
    return 
  end
  local hw_type = raw:byte(15) * 256 + raw:byte(16)
  local proto_type = raw:byte(17) * 256 + raw:byte(18)
  local hw_len = raw:byte(19)
  local proto_len = raw:byte(20)
  if not (hw_type == 1 and proto_type == 0x0800 and hw_len == 6 and proto_len == 4) then
    return 
  end
  local mac_off = 7
  local all_zero = true
  for i = 0, 5 do
    if raw:byte(mac_off + i) ~= 0 then
      all_zero = false
      break
    end
  end
  if all_zero then
    return 
  end
  local msg = build_learn_msg(raw, 29, 4, mac_off)
  local ok = write_learn(learn_wfd, msg)
  if ok then
    return log_debug({
      action = "arp_learned",
      mac = fmt_mac(raw, mac_off),
      ip = tostring(raw:byte(29)) .. "." .. tostring(raw:byte(30)) .. "." .. tostring(raw:byte(31)) .. "." .. tostring(raw:byte(32))
    })
  end
end
local process_ipv6
process_ipv6 = function(raw, len, learn_wfd)
  if len < NDP_MIN_LEN then
    return 
  end
  local next_header = raw:byte(21)
  local icmpv6_type = raw:byte(55)
  if not (next_header == ICMPV6_PROTO) then
    return 
  end
  if not (icmpv6_type == ICMPV6_TYPE_NS or icmpv6_type == ICMPV6_TYPE_NA) then
    return 
  end
  local src_first = raw:byte(23)
  if src_first == 0xff then
    return 
  end
  local all_zero = true
  for i = 23, 38 do
    if raw:byte(i) ~= 0 then
      all_zero = false
      break
    end
  end
  if all_zero then
    return 
  end
  local mac_off = 7
  local all_zero_mac = true
  for i = 0, 5 do
    if raw:byte(mac_off + i) ~= 0 then
      all_zero_mac = false
      break
    end
  end
  if all_zero_mac then
    return 
  end
  local msg = build_learn_msg(raw, 23, 16, mac_off)
  local ok = write_learn(learn_wfd, msg)
  if ok then
    return log_debug({
      action = "ndp_learned",
      mac = fmt_mac(raw, mac_off),
      ip = fmt_ipv6(raw, 23),
      type = icmpv6_type == ICMPV6_TYPE_NS and "NS" or "NA"
    })
  end
end
local run
run = function(ifname, learn_wfd)
  set_action_prefix("arp_")
  local ifindex = tonumber(C.if_nametoindex(ifname))
  if ifindex == 0 then
    log_warn({
      action = "ifindex_failed",
      ifname = ifname
    })
    return 
  end
  local arp_fd = open_socket(ETH_P_ARP, ifindex)
  if not (arp_fd) then
    log_warn({
      action = "socket_failed",
      proto = "ARP",
      ifname = ifname
    })
    return 
  end
  local ip6_fd = open_socket(ETH_P_IPV6, ifindex)
  if not (ip6_fd) then
    log_warn({
      action = "socket_failed",
      proto = "IPv6",
      ifname = ifname
    })
    libc.close(arp_fd)
    return 
  end
  log_info({
    action = "start",
    ifname = ifname,
    ifindex = ifindex
  })
  local pfds = ffi.new("struct pollfd[2]")
  pfds[0].fd = arp_fd
  pfds[0].events = POLLIN
  pfds[1].fd = ip6_fd
  pfds[1].events = POLLIN
  local buf = ffi.new("uint8_t[2048]")
  local buf_len = 2048
  local bit = require("bit")
  while true do
    C.poll(pfds, 2, 5000)
    if bit.band(pfds[0].revents, POLLIN) ~= 0 then
      local n = C.recv(arp_fd, buf, buf_len, 0)
      if n >= ARP_MIN_LEN then
        process_arp(ffi.string(buf, n), n, learn_wfd)
      end
    end
    if bit.band(pfds[1].revents, POLLIN) ~= 0 then
      local n = C.recv(ip6_fd, buf, buf_len, 0)
      if n >= NDP_MIN_LEN then
        process_ipv6(ffi.string(buf, n), n, learn_wfd)
      end
    end
  end
end
return {
  run = run
}
