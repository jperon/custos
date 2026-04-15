local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local bit = require("bit")
local AF_PACKET = 17
local SOCK_RAW = 3
local ETH_P_ALL = 0x0300
local ETH_P_IP = 0x0008
local ETH_P_IPV6 = 0xDD86
local PROTO_TCP = 6
local AF_INET = 2
local AF_INET6 = 10
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
  local len = #raw
  if len < 14 + 20 + 20 then
    return nil
  end
  local p = ffi.cast("const uint8_t*", raw)
  local eth_dst = ffi.string(p, 6)
  local eth_src = ffi.string(p + 6, 6)
  local ethertype = r16(p, 12)
  local ip_ver = nil
  local ip_off = 14
  if ethertype == 0x0800 then
    ip_ver = 4
  elseif ethertype == 0x86DD then
    ip_ver = 6
  else
    return nil
  end
  if ip_ver == 4 then
    if len < ip_off + 20 then
      return nil
    end
    local ver = bit.rshift(p[ip_off], 4)
    if ver ~= 4 then
      return nil
    end
    local ihl = bit.band(p[ip_off], 0x0F) * 4
    if p[ip_off + 9] ~= PROTO_TCP then
      return nil
    end
    local tcp_off = ip_off + ihl
    if len < tcp_off + 20 then
      return nil
    end
    local ip_src_raw = ffi.string(p + ip_off + 12, 4)
    local ip_dst_raw = ffi.string(p + ip_off + 16, 4)
    local ip_src = string.format("%d.%d.%d.%d", p[ip_off + 12], p[ip_off + 13], p[ip_off + 14], p[ip_off + 15])
    local ip_dst = string.format("%d.%d.%d.%d", p[ip_off + 16], p[ip_off + 17], p[ip_off + 18], p[ip_off + 19])
    local sport = r16(p, tcp_off)
    local dport = r16(p, tcp_off + 2)
    local seq = r32(p, tcp_off + 4)
    local flags = p[tcp_off + 13]
    return {
      eth_src = eth_src,
      eth_dst = eth_dst,
      ip_src_raw = ip_src_raw,
      ip_dst_raw = ip_dst_raw,
      ip_src = ip_src,
      ip_dst = ip_dst,
      sport = sport,
      dport = dport,
      seq = seq,
      flags = flags,
      ip_off = ip_off,
      tcp_off = tcp_off,
      ip_ver = ip_ver,
      ihl = ihl
    }
  end
  if ip_ver == 6 then
    if len < ip_off + 40 then
      return nil
    end
    if p[ip_off + 6] ~= PROTO_TCP then
      return nil
    end
    local tcp_off = ip_off + 40
    if len < tcp_off + 20 then
      return nil
    end
    local ip_src_raw = ffi.string(p + ip_off + 8, 16)
    local ip_dst_raw = ffi.string(p + ip_off + 24, 16)
    local sport = r16(p, tcp_off)
    local dport = r16(p, tcp_off + 2)
    local seq = r32(p, tcp_off + 4)
    local flags = p[tcp_off + 13]
    return {
      eth_src = eth_src,
      eth_dst = eth_dst,
      ip_src_raw = ip_src_raw,
      ip_dst_raw = ip_dst_raw,
      sport = sport,
      dport = dport,
      seq = seq,
      flags = flags,
      ip_off = ip_off,
      tcp_off = tcp_off,
      ip_ver = ip_ver,
      ihl = 40
    }
  end
  return nil
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
    local eth_off = 0
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
return {
  parse_syn = parse_syn,
  build_response_frames = build_response_frames,
  open_raw_socket = open_raw_socket,
  send_frame = send_frame,
  r16 = r16,
  r32 = r32,
  w16 = w16,
  w32 = w32,
  inet_sum = inet_sum,
  fold_cksum = fold_cksum
}
