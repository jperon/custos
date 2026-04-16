--- TCP packet parsing and frame forge helpers for the Q2 captive portal worker.
-- Provides minimal TCP header parsing (flags, seq, ack, ports) and frame
-- construction (SYN-ACK, HTTP 302, FIN-ACK) for use with AF_PACKET raw sockets.
-- @module parse.tcp

{ :ffi, :libc } = require "ffi_defs"
bit = require "bit"

AF_PACKET   = 17
SOCK_RAW    = 3
SOCK_DGRAM  = 2
ETH_P_ALL   = 0x0300  -- htons(0x0003)
ETH_P_IP    = 0x0008  -- htons(0x0800)
ETH_P_IPV6  = 0xDD86  -- htons(0x86DD)
PROTO_TCP   = 6
AF_INET     = 2
AF_INET6    = 10

-- ── Byte-level helpers (0-based FFI pointer, big-endian) ─────────

--- Read big-endian uint16 from FFI pointer at 0-based offset.
-- @tparam cdata p uint8_t pointer.
-- @tparam number o 0-based byte offset.
-- @treturn number uint16 value.
r16 = (p, o) ->
  bit.bor bit.lshift(p[o], 8), p[o + 1]

--- Read big-endian uint32 from FFI pointer at 0-based offset.
-- @tparam cdata p uint8_t pointer.
-- @tparam number o 0-based byte offset.
-- @treturn number uint32 value.
r32 = (p, o) ->
  tonumber ffi.cast "uint32_t",
    bit.bor(
      bit.lshift(p[o],   24),
      bit.lshift(p[o+1], 16),
      bit.lshift(p[o+2],  8),
      p[o+3])

--- Write big-endian uint16 into mutable FFI pointer at 0-based offset.
-- @tparam cdata p Mutable uint8_t pointer.
-- @tparam number o 0-based byte offset.
-- @tparam number v uint16 value to write.
w16 = (p, o, v) ->
  p[o]   = bit.band bit.rshift(v, 8), 0xFF
  p[o+1] = bit.band v, 0xFF

--- Write big-endian uint32 into mutable FFI pointer at 0-based offset.
-- @tparam cdata p Mutable uint8_t pointer.
-- @tparam number o 0-based byte offset.
-- @tparam number v uint32 value to write.
w32 = (p, o, v) ->
  p[o]   = bit.band bit.rshift(v, 24), 0xFF
  p[o+1] = bit.band bit.rshift(v, 16), 0xFF
  p[o+2] = bit.band bit.rshift(v,  8), 0xFF
  p[o+3] = bit.band v, 0xFF

-- ── TCP header parsing ───────────────────────────────────────────

--- Parse a TCP SYN from a raw Ethernet frame (NFQUEUE bridge mode, eth_offset=14).
-- @tparam string raw Raw Ethernet frame.
-- @treturn table|nil Parsed SYN fields, or nil on error.
parse_syn = (raw) ->
  len = #raw
  return nil if len < 14 + 20 + 20  -- Ethernet + IPv4 min + TCP min

  p = ffi.cast "const uint8_t*", raw

  -- Ethernet header (14 bytes)
  eth_dst = ffi.string p,     6
  eth_src = ffi.string p + 6, 6

  ethertype = r16 p, 12

  ip_ver = nil
  ip_off = 14

  if ethertype == 0x0800       -- IPv4
    ip_ver = 4
  elseif ethertype == 0x86DD   -- IPv6
    ip_ver = 6
  else
    return nil  -- not IP

  -- IP header
  if ip_ver == 4
    return nil if len < ip_off + 20
    ver = bit.rshift p[ip_off], 4
    return nil if ver != 4
    ihl = bit.band(p[ip_off], 0x0F) * 4
    return nil if p[ip_off + 9] != PROTO_TCP
    tcp_off = ip_off + ihl
    return nil if len < tcp_off + 20
    ip_src_raw = ffi.string p + ip_off + 12, 4
    ip_dst_raw = ffi.string p + ip_off + 16, 4
    ip_src = string.format "%d.%d.%d.%d",
      p[ip_off+12], p[ip_off+13], p[ip_off+14], p[ip_off+15]
    ip_dst = string.format "%d.%d.%d.%d",
      p[ip_off+16], p[ip_off+17], p[ip_off+18], p[ip_off+19]
    sport   = r16 p, tcp_off
    dport   = r16 p, tcp_off + 2
    seq     = r32 p, tcp_off + 4
    flags   = p[tcp_off + 13]
    return {
      :eth_src, :eth_dst
      :ip_src_raw, :ip_dst_raw
      :ip_src, :ip_dst
      :sport, :dport, :seq, :flags
      :ip_off, :tcp_off, :ip_ver, :ihl
    }

  if ip_ver == 6
    return nil if len < ip_off + 40
    -- Only handle TCP with no extension headers for simplicity.
    return nil if p[ip_off + 6] != PROTO_TCP
    tcp_off = ip_off + 40
    return nil if len < tcp_off + 20
    ip_src_raw = ffi.string p + ip_off + 8,  16
    ip_dst_raw = ffi.string p + ip_off + 24, 16
    sport   = r16 p, tcp_off
    dport   = r16 p, tcp_off + 2
    seq     = r32 p, tcp_off + 4
    flags   = p[tcp_off + 13]
    return {
      :eth_src, :eth_dst
      :ip_src_raw, :ip_dst_raw
      :sport, :dport, :seq, :flags
      :ip_off, :tcp_off, :ip_ver, ihl: 40
    }

  nil

-- ── Checksum helpers ─────────────────────────────────────────────

--- Internet checksum over a byte buffer (RFC 1071).
-- @tparam cdata p uint8_t pointer.
-- @tparam number off 0-based start offset.
-- @tparam number len Number of bytes to sum.
-- @treturn number Running sum (not yet one-complemented).
inet_sum = (p, off, len) ->
  sum = 0
  i = off
  while i + 1 < off + len
    sum += r16 p, i
    i += 2
  if (len % 2) == 1
    sum += bit.lshift p[off + len - 1], 8
  sum

--- Fold and one-complement a running Internet checksum sum.
-- @tparam number sum Running sum from inet_sum.
-- @treturn number Final 16-bit checksum value.
fold_cksum = (sum) ->
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  bit.band bit.bnot(sum), 0xFFFF

--- Compute IPv4 TCP checksum.
-- @tparam cdata buf Mutable uint8_t* packet buffer.
-- @tparam number ip_off 0-based offset of IPv4 header.
-- @tparam number tcp_off 0-based offset of TCP header.
-- @tparam number pkt_len Total buffer length.
tcp4_cksum = (buf, ip_off, tcp_off, pkt_len) ->
  buf[tcp_off + 16] = 0
  buf[tcp_off + 17] = 0
  tcp_len = pkt_len - tcp_off
  sum = inet_sum buf, ip_off + 12, 8  -- src + dst IPv4
  sum += PROTO_TCP
  sum += tcp_len
  sum += inet_sum buf, tcp_off, tcp_len
  fold_cksum sum

--- Compute IPv6 TCP checksum.
-- @tparam cdata buf Mutable uint8_t* packet buffer.
-- @tparam number ip_off 0-based offset of IPv6 header.
-- @tparam number tcp_off 0-based offset of TCP header.
-- @tparam number pkt_len Total buffer length.
tcp6_cksum = (buf, ip_off, tcp_off, pkt_len) ->
  buf[tcp_off + 16] = 0
  buf[tcp_off + 17] = 0
  tcp_len = pkt_len - tcp_off
  sum = inet_sum buf, ip_off + 8, 32  -- src(16) + dst(16) IPv6
  sum += tcp_len
  sum += PROTO_TCP
  sum += inet_sum buf, tcp_off, tcp_len
  fold_cksum sum

--- Compute IPv4 header checksum in-place.
-- @tparam cdata buf Mutable uint8_t* packet buffer.
-- @tparam number ip_off 0-based offset of IPv4 header.
-- @tparam number ihl IPv4 header length in bytes.
ip4_cksum = (buf, ip_off, ihl) ->
  buf[ip_off + 10] = 0
  buf[ip_off + 11] = 0
  cksum = fold_cksum inet_sum(buf, ip_off, ihl)
  w16 buf, ip_off + 10, cksum

-- ── Frame forge ──────────────────────────────────────────────────

--- Parse a TCP SYN from a raw IP packet (NFQUEUE router mode, no Ethernet header).
-- @tparam string raw Raw IP packet (Lua string from nfq_get_payload in router mode).
-- @treturn table|nil Parsed SYN fields (no eth_src/eth_dst), or nil on error.
parse_syn_ip = (raw) ->
  len = #raw
  return nil if len < 20 + 20  -- IPv4 min + TCP min
  p = ffi.cast "const uint8_t*", raw
  ip_off = 0
  ver = bit.rshift p[0], 4
  return nil if ver != 4  -- IPv6 not handled here
  return nil if p[9] != PROTO_TCP
  ihl = bit.band(p[0], 0x0F) * 4
  tcp_off = ip_off + ihl
  return nil if len < tcp_off + 20
  ip_src_raw = ffi.string p + 12, 4
  ip_dst_raw = ffi.string p + 16, 4
  ip_src = string.format "%d.%d.%d.%d", p[12], p[13], p[14], p[15]
  ip_dst = string.format "%d.%d.%d.%d", p[16], p[17], p[18], p[19]
  sport  = r16 p, tcp_off
  dport  = r16 p, tcp_off + 2
  seq    = r32 p, tcp_off + 4
  flags  = p[tcp_off + 13]
  { :ip_src_raw, :ip_dst_raw, :ip_src, :ip_dst
    :sport, :dport, :seq, :flags
    :ip_off, :tcp_off, :ihl, ip_ver: 4 }

--- Build Ethernet frames (bridge mode) or IP packets (router mode) for the TCP redirect.
-- @tparam table syn   Parsed SYN (from parse_syn or parse_syn_ip).
-- @tparam string redirect_url  Full HTTPS redirect URL.
-- @tparam boolean eth  true = include Ethernet header (bridge), false = IP only (router).
-- @treturn string, string, string  SYN-ACK, DATA, FIN-ACK.
build_response_frames = (syn, redirect_url, eth = true) ->
  -- Random ISN for our side (server).
  isn = math.random 0, 0x7FFFFFFF

  http_body = "HTTP/1.1 302 Found\r\nLocation: #{redirect_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  http_len  = #http_body

  -- ── SYN-ACK ──────────────────────────────────────────────────
  -- Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes for IPv4
  -- Ethernet(14) + IPv6(40) + TCP(20) = 74 bytes for IPv6

  build_frame = (tcp_flags, payload_str, our_seq, their_ack) ->
    payload_len = payload_str and #payload_str or 0
    ip_off   = if eth then 14 else 0
    tcp_off  = if syn.ip_ver == 4 then ip_off + 20 else ip_off + 40
    pkt_len  = tcp_off + 20 + payload_len
    buf = ffi.new "uint8_t[?]", pkt_len
    ffi.fill buf, pkt_len, 0

    -- Ethernet header: swap src/dst (bridge mode only)
    if eth
      ffi.copy buf,     syn.eth_dst, 6
      ffi.copy buf + 6, syn.eth_src, 6
      if syn.ip_ver == 4
        w16 buf, 12, 0x0800
      else
        w16 buf, 12, 0x86DD

    if syn.ip_ver == 4
      -- IPv4 header
      buf[ip_off]     = 0x45    -- version=4, IHL=5
      buf[ip_off + 8] = 64      -- TTL
      buf[ip_off + 9] = PROTO_TCP
      w16 buf, ip_off + 2, pkt_len - ip_off
      -- src = original dst, dst = original src (swap)
      ffi.copy buf + ip_off + 12, syn.ip_dst_raw, 4
      ffi.copy buf + ip_off + 16, syn.ip_src_raw, 4
    else
      -- IPv6 header
      buf[ip_off] = 0x60          -- version=6
      w16 buf, ip_off + 4, 20 + payload_len  -- payload length
      buf[ip_off + 6]  = PROTO_TCP
      buf[ip_off + 7]  = 64       -- hop limit
      ffi.copy buf + ip_off + 8,  syn.ip_dst_raw, 16
      ffi.copy buf + ip_off + 24, syn.ip_src_raw, 16

    -- TCP header
    w16 buf, tcp_off,     syn.dport    -- sport = original dport (80)
    w16 buf, tcp_off + 2, syn.sport    -- dport = original sport
    w32 buf, tcp_off + 4, our_seq
    w32 buf, tcp_off + 8, their_ack
    buf[tcp_off + 12] = 0x50          -- data offset = 5 (20 bytes), no options
    buf[tcp_off + 13] = tcp_flags
    w16 buf, tcp_off + 14, 65535      -- window size

    -- Copy payload if any
    if payload_str and payload_len > 0
      ffi.copy buf + tcp_off + 20, payload_str, payload_len

    -- Checksums
    if syn.ip_ver == 4
      cksum = tcp4_cksum buf, ip_off, tcp_off, pkt_len
      w16 buf, tcp_off + 16, cksum
      ip4_cksum buf, ip_off, 20
    else
      cksum = tcp6_cksum buf, ip_off, tcp_off, pkt_len
      w16 buf, tcp_off + 16, cksum

    ffi.string buf, pkt_len

  their_seq_plus1 = (syn.seq + 1) % 0x100000000

  -- SYN-ACK: flags=0x12 (SYN|ACK), seq=isn, ack=client_seq+1
  syn_ack = build_frame 0x12, nil, isn, their_seq_plus1

  -- DATA (ACK + HTTP 302): flags=0x18 (PSH|ACK), seq=isn+1, ack=client_seq+1
  data    = build_frame 0x18, http_body, (isn + 1) % 0x100000000, their_seq_plus1

  -- FIN-ACK: flags=0x11 (FIN|ACK), seq=isn+1+http_len, ack=client_seq+1
  fin_ack = build_frame 0x11, nil, (isn + 1 + http_len) % 0x100000000, their_seq_plus1

  syn_ack, data, fin_ack

-- ── AF_PACKET sender ─────────────────────────────────────────────

--- Open an AF_PACKET SOCK_RAW socket (bridge mode: caller builds Ethernet frame).
-- @tparam string ifname  Network interface name.
-- @treturn number|nil    Socket fd, or nil + error message.
open_raw_socket = (ifname) ->
  fd = libc.socket AF_PACKET, SOCK_RAW, ETH_P_ALL
  return nil, "socket() failed: #{ffi.errno!}" if fd < 0
  fd

--- Open an AF_PACKET SOCK_DGRAM socket (router mode: kernel handles Ethernet).
-- @tparam string ifname  Network interface name.
-- @treturn number|nil    Socket fd, or nil + error message.
open_dgram_socket = (ifname) ->
  fd = libc.socket AF_PACKET, SOCK_DGRAM, ETH_P_IP
  return nil, "socket() failed: #{ffi.errno!}" if fd < 0
  fd

--- Send a raw IP packet via AF_PACKET SOCK_DGRAM (router mode).
-- The kernel resolves the destination MAC automatically.
-- @tparam number fd       AF_PACKET SOCK_DGRAM socket fd.
-- @tparam string pkt      IP packet as a Lua string.
-- @tparam number ifindex  Interface index.
-- @treturn boolean  true on success.
send_packet = (fd, pkt, ifindex) ->
  sll = ffi.new "struct sockaddr_ll"
  ffi.fill sll, ffi.sizeof(sll), 0
  sll.sll_family   = AF_PACKET
  sll.sll_protocol = ETH_P_IP
  sll.sll_ifindex  = ifindex
  n = libc.sendto fd, pkt, #pkt, 0,
    ffi.cast("const struct sockaddr*", sll), ffi.sizeof(sll)
  n == #pkt

--- Send a raw Ethernet frame via AF_PACKET on the given interface index.
-- @tparam number fd       AF_PACKET socket fd.
-- @tparam string frame    Ethernet frame as a Lua string.
-- @tparam number ifindex  Interface index (from if_nametoindex).
-- @treturn boolean  true on success.
send_frame = (fd, frame, ifindex) ->
  sll = ffi.new "struct sockaddr_ll"
  ffi.fill sll, ffi.sizeof(sll), 0
  sll.sll_family   = AF_PACKET
  sll.sll_protocol = ETH_P_ALL
  sll.sll_ifindex  = ifindex
  n = libc.sendto fd, frame, #frame, 0,
    ffi.cast("const struct sockaddr*", sll), ffi.sizeof(sll)
  n == #frame

{ :parse_syn, :parse_syn_ip, :build_response_frames
  :open_raw_socket, :send_frame
  :open_dgram_socket, :send_packet
  :r16, :r32, :w16, :w32, :inet_sum, :fold_cksum }
