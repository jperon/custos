local ffi, libc, libnfq
do
  local _obj_0 = require("ffi_defs")
  ffi, libc, libnfq = _obj_0.ffi, _obj_0.libc, _obj_0.libnfq
end
local QUEUE_CAPTIVE
QUEUE_CAPTIVE = require("config").QUEUE_CAPTIVE
local parse_eth
parse_eth = require("ipparse.l2.ethernet").parse
local parse_ip, l3_proto
do
  local _obj_0 = require("ipparse.l3.ip")
  parse_ip, l3_proto = _obj_0.parse, _obj_0.proto
end
local parse_tcp
parse_tcp = require("ipparse.l4.tcp").parse
local run_queue, NF_ACCEPT, NF_DROP
do
  local _obj_0 = require("nfq_loop")
  run_queue, NF_ACCEPT, NF_DROP = _obj_0.run_queue, _obj_0.NF_ACCEPT, _obj_0.NF_DROP
end
local log_info, log_warn, log_error
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error
end
local bit = require("bit")
local sp
sp = require("ipparse.lib.pack_compat").pack
local AF_PACKET = 17
local SOCK_RAW = 3
local ETH_P_ALL = 0x0300
local PROTO_TCP = 6
local r16
r16 = function(p, o)
  return bit.bor(bit.lshift(p[o], 8), p[o + 1])
end
local r32
r32 = function(p, o)
  return tonumber(ffi.cast("uint32_t", bit.bor(bit.lshift(p[o], 24), bit.lshift(p[o + 1], 16), bit.lshift(p[o + 2], 8), p[o + 3])))
end
local w16
w16 = function(p, o, v)
  p[o] = bit.band(bit.rshift(v, 8), 0xFF)
  p[o + 1] = bit.band(v, 0xFF)
end
local w32
w32 = function(p, o, v)
  p[o] = bit.band(bit.rshift(v, 24), 0xFF)
  p[o + 1] = bit.band(bit.rshift(v, 16), 0xFF)
  p[o + 2] = bit.band(bit.rshift(v, 8), 0xFF)
  p[o + 3] = bit.band(v, 0xFF)
end
local parse_syn
parse_syn = function(raw)
  local eth, eth_off = parse_eth(raw)
  if not (eth) then
    return nil
  end
  local ip, ip_off = parse_ip(raw, eth_off, eth.protocol)
  if not (ip) then
    return nil
  end
  local tcp, tcp_off = parse_tcp(raw, ip.data_off)
  if not (tcp) then
    return nil
  end
  return {
    eth_src = eth.src,
    eth_dst = eth.dst,
    ip_ver = ip.version,
    ip_src_raw = (function()
      if ip.version == 4 then
        return ip.src
      else
        return ffi.string(ffi.cast("const uint8_t*", ip.src), 16)
      end
    end)(),
    ip_dst_raw = (function()
      if ip.version == 4 then
        return ip.dst
      else
        return ffi.string(ffi.cast("const uint8_t*", ip.dst), 16)
      end
    end)(),
    ip_src = (function()
      if ip.version == 4 then
        return string.format("%d.%d.%d.%d", ip.src:byte(1), ip.src:byte(2), ip.src:byte(3), ip.src:byte(4))
      else
        return ip.ip2s(ip.src)
      end
    end)(),
    ip_dst = (function()
      if ip.version == 4 then
        return string.format("%d.%d.%d.%d", ip.dst:byte(1), ip.dst:byte(2), ip.dst:byte(3), ip.dst:byte(4))
      else
        return ip.ip2s(ip.dst)
      end
    end)(),
    sport = tcp.spt,
    dport = tcp.dpt,
    seq = tcp.seq_n,
    flags = tcp.flags,
    ip_off = ip_off,
    tcp_off = ip.data_off,
    ihl = (function()
      if ip.version == 4 then
        return (ip.data_off - ip_off)
      else
        return 40
      end
    end)()
  }
end
local inet_sum
inet_sum = function(p, off, len)
  local sum = 0
  local i = off
  while i + 1 < off + len do
    sum = sum + r16(p, i)
    i = i + 2
  end
  if (len % 2) == 1 then
    sum = sum + bit.lshift(p[off + len - 1], 8)
  end
  return sum
end
local fold_cksum
fold_cksum = function(sum)
  while bit.rshift(sum, 16) ~= 0 do
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  end
  return bit.band(bit.bnot(sum), 0xFFFF)
end
local tcp4_cksum
tcp4_cksum = function(buf, ip_off, tcp_off, pkt_len)
  buf[tcp_off + 16] = 0
  buf[tcp_off + 17] = 0
  local tcp_len = pkt_len - tcp_off
  local sum = inet_sum(buf, ip_off + 12, 8)
  sum = sum + PROTO_TCP
  sum = sum + tcp_len
  sum = sum + inet_sum(buf, tcp_off, tcp_len)
  return fold_cksum(sum)
end
local tcp6_cksum
tcp6_cksum = function(buf, ip_off, tcp_off, pkt_len)
  buf[tcp_off + 16] = 0
  buf[tcp_off + 17] = 0
  local tcp_len = pkt_len - tcp_off
  local sum = inet_sum(buf, ip_off + 8, 32)
  sum = sum + tcp_len
  sum = sum + PROTO_TCP
  sum = sum + inet_sum(buf, tcp_off, tcp_len)
  return fold_cksum(sum)
end
local ip4_cksum
ip4_cksum = function(buf, ip_off, ihl)
  buf[ip_off + 10] = 0
  buf[ip_off + 11] = 0
  local cksum = fold_cksum(inet_sum(buf, ip_off, ihl))
  return w16(buf, ip_off + 10, cksum)
end
local build_response_frames
build_response_frames = function(syn, redirect_url)
  local isn = math.random(0, 0x7FFFFFFF)
  local http_body = "HTTP/1.1 302 Found\r\nLocation: " .. tostring(redirect_url) .. "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  local http_len = #http_body
  local build_frame
  build_frame = function(tcp_flags, payload_str, our_seq, their_ack)
    local payload_len = payload_str and #payload_str or 0
    local ip_off = 14
    local tcp_off
    if syn.ip_ver == 4 then
      tcp_off = ip_off + 20
    else
      tcp_off = ip_off + 40
    end
    local pkt_len = tcp_off + 20 + payload_len
    local buf = ffi.new("uint8_t[?]", pkt_len)
    ffi.fill(buf, pkt_len, 0)
    ffi.copy(buf, syn.eth_dst, 6)
    ffi.copy(buf + 6, syn.eth_src, 6)
    if syn.ip_ver == 4 then
      w16(buf, 12, 0x0800)
    else
      w16(buf, 12, 0x86DD)
    end
    if syn.ip_ver == 4 then
      buf[ip_off] = 0x45
      buf[ip_off + 8] = 64
      buf[ip_off + 9] = PROTO_TCP
      w16(buf, ip_off + 2, pkt_len - ip_off)
      ffi.copy(buf + ip_off + 12, syn.ip_dst_raw, 4)
      ffi.copy(buf + ip_off + 16, syn.ip_src_raw, 4)
    else
      buf[ip_off] = 0x60
      w16(buf, ip_off + 4, 20 + payload_len)
      buf[ip_off + 6] = PROTO_TCP
      buf[ip_off + 7] = 64
      ffi.copy(buf + ip_off + 8, syn.ip_dst_raw, 16)
      ffi.copy(buf + ip_off + 24, syn.ip_src_raw, 16)
    end
    w16(buf, tcp_off, syn.dport)
    w16(buf, tcp_off + 2, syn.sport)
    w32(buf, tcp_off + 4, our_seq)
    w32(buf, tcp_off + 8, their_ack)
    buf[tcp_off + 12] = 0x50
    buf[tcp_off + 13] = tcp_flags
    w16(buf, tcp_off + 14, 65535)
    if payload_str and payload_len > 0 then
      ffi.copy(buf + tcp_off + 20, payload_str, payload_len)
    end
    if syn.ip_ver == 4 then
      local cksum = tcp4_cksum(buf, ip_off, tcp_off, pkt_len)
      w16(buf, tcp_off + 16, cksum)
      ip4_cksum(buf, ip_off, 20)
    else
      local cksum = tcp6_cksum(buf, ip_off, tcp_off, pkt_len)
      w16(buf, tcp_off + 16, cksum)
    end
    return ffi.string(buf, pkt_len)
  end
  local their_seq_plus1 = (syn.seq + 1) % 0x100000000
  local syn_ack = build_frame(0x12, nil, isn, their_seq_plus1)
  local data = build_frame(0x18, http_body, (isn + 1) % 0x100000000, their_seq_plus1)
  local fin_ack = build_frame(0x11, nil, (isn + 1 + http_len) % 0x100000000, their_seq_plus1)
  return syn_ack, data, fin_ack
end
local open_raw_socket
open_raw_socket = function(ifname)
  local fd = libc.socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)
  if fd < 0 then
    return nil, "socket() failed: " .. tostring(ffi.errno())
  end
  return fd
end
local send_frame
send_frame = function(fd, frame, ifindex)
  local sll = ffi.new("struct sockaddr_ll")
  ffi.fill(sll, ffi.sizeof(sll), 0)
  sll.sll_family = AF_PACKET
  sll.sll_protocol = ETH_P_ALL
  sll.sll_ifindex = ifindex
  local n = libc.sendto(fd, frame, #frame, 0, ffi.cast("const struct sockaddr*", sll), ffi.sizeof(sll))
  return n == #frame
end
local raw_fd = nil
local ifindex = nil
local redirect_url = nil
local handle_syn
handle_syn = function(qh_ptr, nfad, pkt_id)
  local payload_ptr = ffi.new("unsigned char*[1]")
  local payload_len = libnfq.nfq_get_payload(nfad, payload_ptr)
  if payload_len <= 0 then
    return NF_DROP
  end
  local raw = ffi.string(payload_ptr[0], payload_len)
  local syn = parse_syn(raw)
  if not (syn) then
    log_warn({
      action = "q2_parse_failed",
      queue = 2,
      len = payload_len
    })
    return NF_DROP
  end
  local send
  send = function(f)
    local res = send_frame(raw_fd, f, ifindex)
    if not (res) then
      log_warn({
        action = "q2_frame_send_error",
        queue = 2,
        ip = syn and syn.ip_src or "unknown"
      })
    end
    return res
  end
  local ok, err = pcall(function()
    local f1, f2, f3 = build_response_frames(syn, redirect_url)
    log_info({
      action = "q2_sending_frames",
      queue = 2,
      ip = syn.ip_src,
      frames = 3
    })
    send(f1)
    send(f2)
    return send(f3)
  end)
  if ok then
    local fields = {
      action = "captive_redirect_q2",
      queue = 2,
      ip = syn.ip_src,
      sport = syn.sport,
      vlan = tonumber(libnfq.nfq_get_nfmark(nfad)) or nil,
      url = redirect_url
    }
    if syn.eth_src then
      fields.mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x", syn.eth_src:byte(1), syn.eth_src:byte(2), syn.eth_src:byte(3), syn.eth_src:byte(4), syn.eth_src:byte(5), syn.eth_src:byte(6))
    end
    log_info(fields)
  else
    log_warn({
      action = "q2_send_failed",
      queue = 2,
      err = tostring(err, {
        ip = syn.ip_src
      })
    })
  end
  return NF_DROP
end
local run
run = function(auth_cfg)
  auth_cfg = auth_cfg or { }
  local ifname = auth_cfg.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"
  local https_port = auth_cfg.port or 33443
  local local_ip = auth_cfg.captive_ip or os.getenv("CAPTIVE_IP") or "127.0.0.1"
  local ok_sock, socket = pcall(require, "socket")
  if ok_sock then
    pcall(function()
      local u = socket.udp()
      pcall(function()
        return u:connect("8.8.8.8", 80)
      end)
      local ip, _ = u:getsockname()
      u:close()
      if ip and ip ~= "" and ip ~= "0.0.0.0" then
        local_ip = ip
      end
    end)
  end
  local host_part = local_ip:find(":", 1, true) and "[" .. tostring(local_ip) .. "]" or local_ip
  redirect_url = "https://" .. tostring(host_part) .. ":" .. tostring(https_port) .. "/"
  local fd, err = open_raw_socket(ifname)
  if not (fd) then
    log_error({
      action = "q2_socket_failed",
      err = err,
      ifname = ifname
    })
    return 
  end
  raw_fd = fd
  ifindex = tonumber(ffi.C.if_nametoindex(ifname))
  if ifindex == 0 then
    log_error({
      action = "q2_ifindex_failed",
      ifname = ifname
    })
    return 
  end
  log_info({
    action = "q2_worker_start",
    ifname = ifname,
    ifindex = ifindex,
    redirect_url = redirect_url
  })
  return run_queue(QUEUE_CAPTIVE, handle_syn)
end
return {
  run = run
}
