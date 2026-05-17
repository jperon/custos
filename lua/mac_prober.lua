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
local log_debug, log_warn
do
  local _obj_0 = require("log")
  log_debug, log_warn = _obj_0.log_debug, _obj_0.log_warn
end
local ip2s
ip2s = require("ipparse.l3.ip").ip2s
local bit = require("bit")
AF_PACKET = 17
SOCK_RAW = 3
local POLLIN = 1
AF_INET6 = 10
local CLOCK_MONOTONIC = 1
local ETH_P_ARP = C.htons(0x0806)
local ETH_P_IPV6 = C.htons(0x86DD)
local ICMPV6_TYPE_NA = 136
local get_ms
get_ms = function()
  local ts = ffi.new("timespec_t")
  libc.clock_gettime(CLOCK_MONOTONIC, ts)
  return tonumber(ts.tv_sec) * 1000 + math.floor(tonumber(ts.tv_nsec) / 1000000)
end
local ones_add
ones_add = function(s, acc)
  local i = 1
  local n = #s
  while i <= n - 1 do
    acc = acc + (s:byte(i) * 256 + s:byte(i + 1))
    i = i + 2
  end
  if i == n then
    acc = acc + (s:byte(i) * 256)
  end
  return acc
end
local fold16
fold16 = function(acc)
  while acc > 0xFFFF do
    acc = bit.band(acc, 0xFFFF) + bit.rshift(acc, 16)
  end
  return bit.bxor(acc, 0xFFFF)
end
local icmpv6_cksum
icmpv6_cksum = function(src6, dst6, payload)
  local plen = #payload
  local pseudo = src6 .. dst6 .. string.char(bit.rshift(bit.band(plen, 0xFF000000), 24), bit.rshift(bit.band(plen, 0x00FF0000), 16), bit.rshift(bit.band(plen, 0x0000FF00), 8), bit.band(plen, 0xFF)) .. "\x00\x00\x00\x3a"
  return fold16(ones_add(payload, ones_add(pseudo, 0)))
end
local ip4_to_bin
ip4_to_bin = function(s)
  local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
  if not (a) then
    return nil
  end
  return string.char(tonumber(a), tonumber(b), tonumber(c), tonumber(d))
end
local ip6_to_bin
ip6_to_bin = function(s)
  local buf = ffi.new("uint8_t[16]")
  if C.inet_pton(AF_INET6, s, buf) ~= 1 then
    return nil
  end
  return ffi.string(buf, 16)
end
local fmt_mac
fmt_mac = function(s, off)
  return string.format("%02x:%02x:%02x:%02x:%02x:%02x", s:byte(off), s:byte(off + 1), s:byte(off + 2), s:byte(off + 3), s:byte(off + 4), s:byte(off + 5))
end
local read_own_mac
read_own_mac = function(ifname)
  local fh = io.open("/sys/class/net/" .. tostring(ifname) .. "/address", "r")
  if not (fh) then
    return nil
  end
  local s = (fh:read("*a")):gsub("%s+", "")
  fh:close()
  local a, b, c, d, e, f = s:match("^(%x+):(%x+):(%x+):(%x+):(%x+):(%x+)$")
  if not (a) then
    return nil
  end
  return string.char(tonumber(a, 16), tonumber(b, 16), tonumber(c, 16), tonumber(d, 16), tonumber(e, 16), tonumber(f, 16))
end
local read_own_ip6
read_own_ip6 = function(ifname)
  local fh = io.open("/proc/net/if_inet6", "r")
  if not (fh) then
    return nil
  end
  local result = nil
  for line in fh:lines() do
    local tok = { }
    for p in line:gmatch("%S+") do
      tok[#tok + 1] = p
    end
    if #tok >= 6 and tok[6] == ifname and tok[4] == "20" then
      local hex = tok[1]
      local bytes = ""
      for i = 1, 32, 2 do
        bytes = bytes .. string.char(tonumber(hex:sub(i, i + 1), 16))
      end
      if #bytes == 16 then
        result = bytes
        break
      end
    end
  end
  fh:close()
  return result
end
local open_socket
open_socket = function(proto, ifindex)
  local fd = C.socket(AF_PACKET, SOCK_RAW, proto)
  if fd < 0 then
    return nil
  end
  local sll = ffi.new("struct sockaddr_ll")
  ffi.fill(sll, ffi.sizeof(sll), 0)
  sll.sll_family = AF_PACKET
  sll.sll_protocol = proto
  sll.sll_ifindex = ifindex
  if C.bind(fd, ffi.cast("struct sockaddr*", sll), ffi.sizeof(sll)) ~= 0 then
    libc.close(fd)
    return nil
  end
  return fd
end
local build_arp_request
build_arp_request = function(our_mac, tgt4_bin)
  local eth = "\xff\xff\xff\xff\xff\xff" .. our_mac .. "\x08\x06"
  local arp = "\x00\x01" .. "\x08\x00" .. "\x06" .. "\x04" .. "\x00\x01" .. our_mac .. "\x00\x00\x00\x00" .. "\x00\x00\x00\x00\x00\x00" .. tgt4_bin
  return eth .. arp
end
local build_ns_frame
build_ns_frame = function(our_mac, our_ip6, tgt6_bin)
  local sol = "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff" .. tgt6_bin:sub(14, 16)
  local eth_dst = "\x33\x33\xff" .. tgt6_bin:sub(14, 16)
  local ns_body = string.char(135, 0, 0, 0) .. "\x00\x00\x00\x00" .. tgt6_bin .. string.char(1, 1) .. our_mac
  local ns_len = #ns_body
  local ip6_hdr = "\x60\x00\x00\x00" .. string.char(0, ns_len) .. "\x3a\xff" .. our_ip6 .. sol
  local ck = icmpv6_cksum(our_ip6, sol, ns_body)
  ns_body = ns_body:sub(1, 2) .. string.char(bit.rshift(ck, 8), bit.band(ck, 0xFF)) .. ns_body:sub(5)
  local eth_hdr = eth_dst .. our_mac .. "\x86\xDD"
  return eth_hdr .. ip6_hdr .. ns_body
end
local send_frame
send_frame = function(fd, ifindex, frame)
  local sll = ffi.new("struct sockaddr_ll")
  ffi.fill(sll, ffi.sizeof(sll), 0)
  sll.sll_family = AF_PACKET
  sll.sll_ifindex = ifindex
  local n = C.sendto(fd, frame, #frame, 0, ffi.cast("const struct sockaddr*", sll), ffi.sizeof(sll))
  return n == #frame
end
local parse_arp_reply
parse_arp_reply = function(raw, len, tgt4_bin)
  if len < 42 then
    return nil, nil
  end
  local hw_type = raw:byte(15) * 256 + raw:byte(16)
  local proto_type = raw:byte(17) * 256 + raw:byte(18)
  local hw_len = raw:byte(19)
  local proto_len = raw:byte(20)
  local op = raw:byte(21) * 256 + raw:byte(22)
  if not (hw_type == 1 and proto_type == 0x0800) then
    return nil, nil
  end
  if not (hw_len == 6 and proto_len == 4) then
    return nil, nil
  end
  if not (op == 2) then
    return nil, nil
  end
  local spa = raw:sub(29, 32)
  if not (spa == tgt4_bin) then
    return nil, nil
  end
  local ip4_str = tostring(raw:byte(29)) .. "." .. tostring(raw:byte(30)) .. "." .. tostring(raw:byte(31)) .. "." .. tostring(raw:byte(32))
  local mac_str = fmt_mac(raw, 23)
  return ip4_str, mac_str
end
local parse_na_reply
parse_na_reply = function(raw, len, tgt6_bin)
  if len < 86 then
    return nil, nil
  end
  local next_hdr = raw:byte(21)
  local icmpv6_type = raw:byte(55)
  if not (next_hdr == 58) then
    return nil, nil
  end
  if not (icmpv6_type == ICMPV6_TYPE_NA) then
    return nil, nil
  end
  local na_target = raw:sub(63, 78)
  if not (na_target == tgt6_bin) then
    return nil, nil
  end
  local mac_str = fmt_mac(raw, 7)
  local ip6_src = ip2s(raw:sub(23, 38))
  if not (ip6_src) then
    return nil, nil
  end
  return ip6_src, mac_str
end
local wait_reply
wait_reply = function(fd, timeout_ms, parse_fn)
  local pfd = ffi.new("struct pollfd[1]")
  pfd[0].fd = fd
  pfd[0].events = POLLIN
  local buf = ffi.new("uint8_t[2048]")
  local start_ms = get_ms()
  while true do
    local remaining = timeout_ms - (get_ms() - start_ms)
    if remaining <= 0 then
      break
    end
    local rc = C.poll(pfd, 1, remaining)
    if rc <= 0 then
      break
    end
    if bit.band(pfd[0].revents, POLLIN) ~= 0 then
      local n = C.recv(fd, buf, 2048, 0)
      if n > 0 then
        local raw = ffi.string(buf, n)
        local mac = parse_fn(raw, n)
        if mac then
          return mac
        end
      end
    end
  end
  return nil
end
local init
init = function(ifname)
  local our_mac = read_own_mac(ifname)
  if not (our_mac) then
    log_warn({
      action = "mac_prober_no_mac",
      ifname = ifname
    })
    return nil
  end
  local ifindex = tonumber(C.if_nametoindex(ifname))
  if ifindex == 0 then
    local errno = tonumber(ffi.C.__errno_location()[0])
    log_warn({
      action = "mac_prober_no_ifindex",
      ifname = ifname,
      errno = errno
    })
    return nil
  end
  local arp_fd = open_socket(ETH_P_ARP, ifindex)
  if not (arp_fd) then
    local errno = tonumber(ffi.C.__errno_location()[0])
    log_warn({
      action = "mac_prober_arp_socket_failed",
      ifname = ifname,
      errno = errno
    })
    return nil
  end
  local our_ip6 = read_own_ip6(ifname)
  local ip6_fd = nil
  if our_ip6 then
    ip6_fd = open_socket(ETH_P_IPV6, ifindex)
    if not (ip6_fd) then
      local errno = tonumber(ffi.C.__errno_location()[0])
      log_warn({
        action = "mac_prober_ip6_socket_failed",
        ifname = ifname,
        errno = errno,
        msg = "NS probes disabled"
      })
    end
  else
    log_warn({
      action = "mac_prober_no_ip6",
      ifname = ifname,
      msg = "no link-local found, NS probes disabled"
    })
  end
  return {
    ifname = ifname,
    ifindex = ifindex,
    our_mac = our_mac,
    our_ip6 = our_ip6,
    arp_fd = arp_fd,
    ip6_fd = ip6_fd
  }
end
local probe_and_wait
probe_and_wait = function(ctx, ip_str, timeout_ms)
  if not (ctx) then
    return nil
  end
  timeout_ms = timeout_ms or 200
  local is_ipv6 = ip_str:find(":", 1, true) ~= nil
  if is_ipv6 then
    if not (ctx.ip6_fd and ctx.our_ip6) then
      return nil
    end
    local tgt_bin = ip6_to_bin(ip_str)
    if not (tgt_bin) then
      return nil
    end
    local frame = build_ns_frame(ctx.our_mac, ctx.our_ip6, tgt_bin)
    if not (frame) then
      return nil
    end
    if not (send_frame(ctx.ip6_fd, ctx.ifindex, frame)) then
      log_warn({
        action = "mac_prober_ns_send_failed",
        ip = ip_str
      })
      return nil
    end
    log_debug({
      action = "mac_prober_ns_sent",
      ip = ip_str
    })
    return wait_reply(ctx.ip6_fd, timeout_ms, function(raw, n)
      local _, mac = parse_na_reply(raw, n, tgt_bin)
      return mac
    end)
  else
    local tgt_bin = ip4_to_bin(ip_str)
    if not (tgt_bin) then
      return nil
    end
    local frame = build_arp_request(ctx.our_mac, tgt_bin)
    if not (send_frame(ctx.arp_fd, ctx.ifindex, frame)) then
      log_warn({
        action = "mac_prober_arp_send_failed",
        ip = ip_str
      })
      return nil
    end
    log_debug({
      action = "mac_prober_arp_sent",
      ip = ip_str
    })
    return wait_reply(ctx.arp_fd, timeout_ms, function(raw, n)
      local _, mac = parse_arp_reply(raw, n, tgt_bin)
      return mac
    end)
  end
end
local send_probe
send_probe = function(ctx, ip_str)
  if not (ctx) then
    return false
  end
  local is_ipv6 = ip_str:find(":", 1, true) ~= nil
  if is_ipv6 then
    if not (ctx.ip6_fd and ctx.our_ip6) then
      return false
    end
    local tgt_bin = ip6_to_bin(ip_str)
    if not (tgt_bin) then
      return false
    end
    local frame = build_ns_frame(ctx.our_mac, ctx.our_ip6, tgt_bin)
    if not (frame) then
      return false
    end
    return send_frame(ctx.ip6_fd, ctx.ifindex, frame)
  else
    local tgt_bin = ip4_to_bin(ip_str)
    if not (tgt_bin) then
      return false
    end
    local frame = build_arp_request(ctx.our_mac, tgt_bin)
    return send_frame(ctx.arp_fd, ctx.ifindex, frame)
  end
end
local parse_arp_frame
parse_arp_frame = function(raw, n)
  if n < 42 then
    return nil, nil
  end
  local hw_type = raw:byte(15) * 256 + raw:byte(16)
  local proto_type = raw:byte(17) * 256 + raw:byte(18)
  local hw_len = raw:byte(19)
  local proto_len = raw:byte(20)
  local op = raw:byte(21) * 256 + raw:byte(22)
  if not (hw_type == 1 and proto_type == 0x0800) then
    return nil, nil
  end
  if not (hw_len == 6 and proto_len == 4) then
    return nil, nil
  end
  if not (op == 2) then
    return nil, nil
  end
  local all_zero = true
  for i = 23, 28 do
    if raw:byte(i) ~= 0 then
      all_zero = false
      break
    end
  end
  if all_zero then
    return nil, nil
  end
  local ip_str = tostring(raw:byte(29)) .. "." .. tostring(raw:byte(30)) .. "." .. tostring(raw:byte(31)) .. "." .. tostring(raw:byte(32))
  local mac_str = fmt_mac(raw, 23)
  return ip_str, mac_str
end
local parse_na_frame
parse_na_frame = function(raw, n)
  if n < 78 then
    return nil, nil
  end
  if not (raw:byte(21) == 58) then
    return nil, nil
  end
  if not (raw:byte(55) == ICMPV6_TYPE_NA) then
    return nil, nil
  end
  local all_zero = true
  for i = 7, 12 do
    if raw:byte(i) ~= 0 then
      all_zero = false
      break
    end
  end
  if all_zero then
    return nil, nil
  end
  local na_target_ip = ip2s(raw:sub(63, 78))
  if not (na_target_ip) then
    return nil, nil
  end
  return na_target_ip, fmt_mac(raw, 7)
end
return {
  init = init,
  probe_and_wait = probe_and_wait,
  send_probe = send_probe,
  parse_arp_frame = parse_arp_frame,
  parse_na_frame = parse_na_frame,
  get_ms = get_ms
}
