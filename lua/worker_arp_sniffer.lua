local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local C, AF_PACKET, SOCK_RAW
do
  local _obj_0 = require("lib.socket")
  C, AF_PACKET, SOCK_RAW = _obj_0.C, _obj_0.AF_PACKET, _obj_0.SOCK_RAW
end
local log_info, log_warn, log_debug, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug, _obj_0.set_action_prefix
end
local ip2s
ip2s = require("ipparse.l3.ip").ip2s
local POLLIN = 1
local ETH_P_ALL = C.htons(0x0003)
local SOL_PACKET = 263
local PACKET_ADD_MEMBERSHIP = 1
local PACKET_MR_PROMISC = 1
local ICMPV6_PROTO = 58
local ICMPV6_TYPE_NS = 135
local ICMPV6_TYPE_NA = 136
local NDP_OPT_TGT_LLA = 2
local ARP_MIN_LEN = 42
local NDP_MIN_LEN = 56
local NDP_OPT_MIN_LEN = 8
local fmt_mac
fmt_mac = function(s, o)
  return string.format("%02x:%02x:%02x:%02x:%02x:%02x", s:byte(o), s:byte(o + 1), s:byte(o + 2), s:byte(o + 3), s:byte(o + 4), s:byte(o + 5))
end
local fmt_ipv6
fmt_ipv6 = function(s, o)
  return ip2s(s:sub(o, o + 15))
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
local extract_tlla
extract_tlla = function(raw, opt_start, len)
  if len < opt_start + NDP_OPT_MIN_LEN then
    return nil
  end
  local offset = opt_start
  while offset + 2 <= len do
    local opt_type = raw:byte(offset)
    local opt_len = raw:byte(offset + 1) * 8
    if opt_len < 2 or opt_len > 255 then
      return nil
    end
    if offset + opt_len > len then
      return nil
    end
    if opt_type == NDP_OPT_TGT_LLA then
      if opt_len >= 8 then
        local mac_start = offset + 2
        local all_zero = true
        for i = 0, 5 do
          if raw:byte(mac_start + i) ~= 0 then
            all_zero = false
            break
          end
        end
        if not (all_zero) then
          return raw:sub(mac_start, mac_start + 5)
        end
      end
    end
    offset = offset + opt_len
  end
  return nil
end
local open_socket
open_socket = function(ifindex)
  local fd = C.socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)
  if fd < 0 then
    return nil
  end
  local sll = ffi.new("struct sockaddr_ll")
  ffi.fill(sll, ffi.sizeof(sll), 0)
  sll.sll_family = AF_PACKET
  sll.sll_protocol = ETH_P_ALL
  sll.sll_ifindex = ifindex
  if C.bind(fd, ffi.cast("struct sockaddr*", sll), ffi.sizeof(sll)) ~= 0 then
    libc.close(fd)
    return nil
  end
  local mreq = ffi.new("struct packet_mreq")
  ffi.fill(mreq, ffi.sizeof(mreq), 0)
  mreq.mr_ifindex = ifindex
  mreq.mr_type = PACKET_MR_PROMISC
  mreq.mr_alen = 0
  if C.setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq, ffi.sizeof(mreq)) ~= 0 then
    log_debug({
      action = "promisc_failed",
      ifindex = ifindex,
      errno = tonumber(ffi.C.__errno_location()[0])
    })
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
  local mac_src_off = 7
  local all_zero_mac = true
  for i = 0, 5 do
    if raw:byte(mac_src_off + i) ~= 0 then
      all_zero_mac = false
      break
    end
  end
  if all_zero_mac then
    return 
  end
  if icmpv6_type == ICMPV6_TYPE_NS then
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
    local msg = build_learn_msg(raw, 23, 16, mac_src_off)
    local ok = write_learn(learn_wfd, msg)
    if ok then
      return log_debug({
        action = "ndp_learned",
        mac = fmt_mac(raw, mac_src_off),
        ip = fmt_ipv6(raw, 23),
        type = "NS"
      })
    end
  else
    if len < 78 then
      return 
    end
    local target_off = 63
    local target_first = raw:byte(target_off)
    if target_first == 0xff then
      return 
    end
    local tlla_mac = extract_tlla(raw, 79, len)
    if tlla_mac then
      local msg = ffi.new("uint8_t[22]")
      for i = 0, 15 do
        msg[i] = raw:byte(target_off + i)
      end
      for i = 0, 5 do
        msg[16 + i] = tlla_mac:byte(i + 1)
      end
      local ok = write_learn(learn_wfd, msg)
      if ok then
        return log_debug({
          action = "ndp_learned",
          mac = fmt_mac(tlla_mac, 1),
          ip = fmt_ipv6(raw, target_off),
          type = "NA",
          tlla = true
        })
      end
    else
      local msg = build_learn_msg(raw, target_off, 16, mac_src_off)
      local ok = write_learn(learn_wfd, msg)
      if ok then
        return log_debug({
          action = "ndp_learned",
          mac = fmt_mac(raw, mac_src_off),
          ip = fmt_ipv6(raw, target_off),
          type = "NA",
          tlla = false
        })
      end
    end
  end
end
local run
run = function(ifnames, learn_wfd)
  set_action_prefix("arp_")
  if type(ifnames) == "string" then
    ifnames = {
      ifnames
    }
  end
  local fds = { }
  for _index_0 = 1, #ifnames do
    local _continue_0 = false
    repeat
      local ifname = ifnames[_index_0]
      local ifindex = tonumber(C.if_nametoindex(ifname))
      if ifindex == 0 then
        local errno = tonumber(ffi.C.__errno_location()[0])
        log_warn({
          action = "ifindex_failed",
          ifname = ifname,
          errno = errno
        })
        _continue_0 = true
        break
      end
      local fd = open_socket(ifindex)
      if fd then
        table.insert(fds, fd)
        log_debug({
          action = "socket_open",
          ifname = ifname,
          ifindex = ifindex
        })
      else
        local errno = tonumber(ffi.C.__errno_location()[0])
        log_warn({
          action = "socket_failed",
          ifname = ifname,
          errno = errno
        })
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  if #fds == 0 then
    log_warn({
      action = "no_sockets",
      interfaces = table.concat(ifnames, ",")
    })
    return 
  end
  log_info({
    action = "start",
    interfaces = table.concat(ifnames, ","),
    sockets = #fds
  })
  local pfds = ffi.new("struct pollfd[?]", #fds)
  for i, fd in ipairs(fds) do
    pfds[i].fd = fd
    pfds[i].events = POLLIN
  end
  local buf = ffi.new("uint8_t[2048]")
  local buf_len = 2048
  local bit = require("bit")
  while true do
    C.poll(pfds, #fds, 5000)
    for i = 0, #fds - 1 do
      if bit.band(pfds[i].revents, POLLIN) ~= 0 then
        local fd = pfds[i].fd
        local n = C.recv(fd, buf, buf_len, 0)
        if n > 14 then
          local raw = ffi.string(buf, n)
          local ethertype = raw:byte(13) * 256 + raw:byte(14)
          if ethertype == 0x0806 and n >= ARP_MIN_LEN then
            process_arp(raw, n, learn_wfd)
          elseif ethertype == 0x86DD and n >= NDP_MIN_LEN then
            process_ipv6(raw, n, learn_wfd)
          end
        end
      end
    end
  end
end
return {
  run = run
}
