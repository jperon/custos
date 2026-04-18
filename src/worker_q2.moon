-- src/worker_q2.moon
-- Worker Q2 : portail captif (bridge mode).
--
-- Reçoit les TCP SYN vers le port 80 non autorisés (NFQUEUE 2).
-- Pour chaque SYN :
--   1. Parse le payload (trame Ethernet complète)
--   2. Forge et envoie via AF_PACKET :
--        a. SYN-ACK
--        b. ACK + HTTP/1.1 302 Found → https://<filtre>:33443/
--        c. FIN-ACK
--   3. Verdict NF_DROP sur le SYN original
--   4. Log structuré

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :QUEUE_CAPTIVE } = require "config"
parse: parse_eth = require "ipparse.l2.ethernet"
parse: parse_ip, proto: l3_proto = require "ipparse.l3.ip"
parse: parse_tcp = require "ipparse.l4.tcp"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_info, :log_warn, :log_error } = require "log"
bit = require "bit"
pack: sp = require "ipparse.lib.pack_compat"

-- ── TCP helper functions (ipparse for parsing, custom for frame forge) ──

AF_PACKET   = 17
SOCK_RAW    = 3
ETH_P_ALL   = 0x0300  -- htons(0x0003)
PROTO_TCP   = 6

-- Byte-level helpers (0-based FFI pointer, big-endian)
r16 = (p, o) -> bit.bor bit.lshift(p[o], 8), p[o + 1]
r32 = (p, o) ->
  tonumber ffi.cast "uint32_t",
    bit.bor(bit.lshift(p[o], 24), bit.lshift(p[o+1], 16),
           bit.lshift(p[o+2], 8), p[o+3])

w16 = (p, o, v) ->
  p[o]   = bit.band bit.rshift(v, 8), 0xFF
  p[o+1] = bit.band v, 0xFF

w32 = (p, o, v) ->
  p[o]   = bit.band bit.rshift(v, 24), 0xFF
  p[o+1] = bit.band bit.rshift(v, 16), 0xFF
  p[o+2] = bit.band bit.rshift(v,  8), 0xFF
  p[o+3] = bit.band v, 0xFF

-- Parse TCP SYN from Ethernet frame using ipparse
parse_syn = (raw) ->
  eth, eth_off = parse_eth raw
  return nil unless eth

  ip, ip_off = parse_ip raw, eth_off, eth.protocol
  return nil unless ip

  tcp, tcp_off = parse_tcp raw, ip.data_off
  return nil unless tcp

  -- Extract fields needed for frame forging
  {
    eth_src: eth.src
    eth_dst: eth.dst
    ip_ver: ip.version
    ip_src_raw: if ip.version == 4 then ip.src else ffi.string(ffi.cast("const uint8_t*", ip.src), 16)
    ip_dst_raw: if ip.version == 4 then ip.dst else ffi.string(ffi.cast("const uint8_t*", ip.dst), 16)
    ip_src: if ip.version == 4 then string.format("%d.%d.%d.%d", ip.src\byte(1), ip.src\byte(2), ip.src\byte(3), ip.src\byte(4)) else ip.ip2s(ip.src)
    ip_dst: if ip.version == 4 then string.format("%d.%d.%d.%d", ip.dst\byte(1), ip.dst\byte(2), ip.dst\byte(3), ip.dst\byte(4)) else ip.ip2s(ip.dst)
    sport: tcp.spt
    dport: tcp.dpt
    seq: tcp.seq_n
    flags: tcp.flags
    ip_off: ip_off
    tcp_off: ip.data_off
    ihl: if ip.version == 4 then (ip.data_off - ip_off) else 40
  }

-- Checksum helpers (keep from original parse/tcp.moon)
inet_sum = (p, off, len) ->
  sum = 0
  i = off
  while i + 1 < off + len
    sum += r16 p, i
    i += 2
  if (len % 2) == 1
    sum += bit.lshift p[off + len - 1], 8
  sum

fold_cksum = (sum) ->
  while bit.rshift(sum, 16) != 0
    sum = bit.band(sum, 0xFFFF) + bit.rshift(sum, 16)
  bit.band bit.bnot(sum), 0xFFFF

tcp4_cksum = (buf, ip_off, tcp_off, pkt_len) ->
  buf[tcp_off + 16] = 0
  buf[tcp_off + 17] = 0
  tcp_len = pkt_len - tcp_off
  sum = inet_sum buf, ip_off + 12, 8
  sum += PROTO_TCP
  sum += tcp_len
  sum += inet_sum buf, tcp_off, tcp_len
  fold_cksum sum

tcp6_cksum = (buf, ip_off, tcp_off, pkt_len) ->
  buf[tcp_off + 16] = 0
  buf[tcp_off + 17] = 0
  tcp_len = pkt_len - tcp_off
  sum = inet_sum buf, ip_off + 8, 32
  sum += tcp_len
  sum += PROTO_TCP
  sum += inet_sum buf, tcp_off, tcp_len
  fold_cksum sum

ip4_cksum = (buf, ip_off, ihl) ->
  buf[ip_off + 10] = 0
  buf[ip_off + 11] = 0
  cksum = fold_cksum inet_sum(buf, ip_off, ihl)
  w16 buf, ip_off + 10, cksum

-- Build Ethernet frames for TCP redirect (keep original logic)
build_response_frames = (syn, redirect_url) ->
  isn = math.random 0, 0x7FFFFFFF
  http_body = "HTTP/1.1 302 Found\r\nLocation: #{redirect_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  http_len  = #http_body

  build_frame = (tcp_flags, payload_str, our_seq, their_ack) ->
    payload_len = payload_str and #payload_str or 0
    ip_off = 14
    tcp_off = if syn.ip_ver == 4 then ip_off + 20 else ip_off + 40
    pkt_len = tcp_off + 20 + payload_len

    buf = ffi.new "uint8_t[?]", pkt_len
    ffi.fill buf, pkt_len, 0

    -- Ethernet header: swap src/dst
    ffi.copy buf,     syn.eth_dst, 6
    ffi.copy buf + 6, syn.eth_src, 6
    if syn.ip_ver == 4
      w16 buf, 12, 0x0800
    else
      w16 buf, 12, 0x86DD

    if syn.ip_ver == 4
      -- IPv4 header
      buf[ip_off]     = 0x45
      buf[ip_off + 8] = 64
      buf[ip_off + 9] = PROTO_TCP
      w16 buf, ip_off + 2, pkt_len - ip_off
      ffi.copy buf + ip_off + 12, syn.ip_dst_raw, 4
      ffi.copy buf + ip_off + 16, syn.ip_src_raw, 4
    else
      -- IPv6 header
      buf[ip_off] = 0x60
      w16 buf, ip_off + 4, 20 + payload_len
      buf[ip_off + 6]  = PROTO_TCP
      buf[ip_off + 7]  = 64
      ffi.copy buf + ip_off + 8,  syn.ip_dst_raw, 16
      ffi.copy buf + ip_off + 24, syn.ip_src_raw, 16

    -- TCP header
    w16 buf, tcp_off,     syn.dport
    w16 buf, tcp_off + 2, syn.sport
    w32 buf, tcp_off + 4, our_seq
    w32 buf, tcp_off + 8, their_ack
    buf[tcp_off + 12] = 0x50
    buf[tcp_off + 13] = tcp_flags
    w16 buf, tcp_off + 14, 65535

    if payload_str and payload_len > 0
      ffi.copy buf + tcp_off + 20, payload_str, payload_len

    if syn.ip_ver == 4
      cksum = tcp4_cksum buf, ip_off, tcp_off, pkt_len
      w16 buf, tcp_off + 16, cksum
      ip4_cksum buf, ip_off, 20
    else
      cksum = tcp6_cksum buf, ip_off, tcp_off, pkt_len
      w16 buf, tcp_off + 16, cksum

    ffi.string buf, pkt_len

  their_seq_plus1 = (syn.seq + 1) % 0x100000000
  syn_ack = build_frame 0x12, nil, isn, their_seq_plus1
  data    = build_frame 0x18, http_body, (isn + 1) % 0x100000000, their_seq_plus1
  fin_ack = build_frame 0x11, nil, (isn + 1 + http_len) % 0x100000000, their_seq_plus1

  syn_ack, data, fin_ack

-- AF_PACKET sender (keep from original)
open_raw_socket = (ifname) ->
  fd = libc.socket AF_PACKET, SOCK_RAW, ETH_P_ALL
  return nil, "socket() failed: #{ffi.errno!}" if fd < 0
  fd

send_frame = (fd, frame, ifindex) ->
  sll = ffi.new "struct sockaddr_ll"
  ffi.fill sll, ffi.sizeof(sll), 0
  sll.sll_family   = AF_PACKET
  sll.sll_protocol = ETH_P_ALL
  sll.sll_ifindex  = ifindex
  n = libc.sendto fd, frame, #frame, 0,
    ffi.cast("const struct sockaddr*", sll), ffi.sizeof(sll)
  n == #frame

-- fd du socket AF_PACKET, ouvert une seule fois au démarrage du worker
raw_fd   = nil
ifindex  = nil

-- URL de redirection vers le portail captif HTTPS.
-- Construite depuis auth_cfg à l'initialisation.
redirect_url = nil

-- ── Callback principal ───────────────────────────────────────────
--- Handle a TCP SYN/80 packet from NFQUEUE 2.
-- Parses the Ethernet frame, forges a TCP 302 redirect response, and drops the SYN.
-- @tparam cdata  qh_ptr  nfq_q_handle pointer
-- @tparam cdata  nfad    nfq_data pointer
-- @tparam number pkt_id  NFQUEUE packet id
-- @treturn number NF_DROP always (response injected via AF_PACKET)
handle_syn = (qh_ptr, nfad, pkt_id) ->
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  return NF_DROP if payload_len <= 0

  raw = ffi.string payload_ptr[0], payload_len

  syn = parse_syn(raw)
  unless syn
    log_warn { action: "q2_parse_failed", queue: 2, len: payload_len }
    return NF_DROP

  send = (f) ->
    res = send_frame raw_fd, f, ifindex
    unless res
      log_warn { action: "q2_frame_send_error", queue: 2, ip: syn and syn.ip_src or "unknown" }
    res

  ok, err = pcall ->
    f1, f2, f3 = build_response_frames syn, redirect_url
    log_info { action: "q2_sending_frames", queue: 2, ip: syn.ip_src, frames: 3 }
    send f1
    send f2
    send f3

  if ok
    fields = {
      action:  "captive_redirect_q2"
      queue:   2
      ip:      syn.ip_src
      sport:   syn.sport
      vlan:    tonumber(libnfq.nfq_get_nfmark nfad) or nil
      url:     redirect_url
    }
    if syn.eth_src
      fields.mac = string.format "%02x:%02x:%02x:%02x:%02x:%02x",
        syn.eth_src\byte(1), syn.eth_src\byte(2), syn.eth_src\byte(3),
        syn.eth_src\byte(4), syn.eth_src\byte(5), syn.eth_src\byte(6)
    log_info fields
  else
    log_warn { action: "q2_send_failed", queue: 2, err: tostring err, ip: syn.ip_src }

  NF_DROP



-- ── Point d'entrée ───────────────────────────────────────────────
--- Start the Q2 captive portal worker.
-- Opens the AF_PACKET socket (SOCK_RAW) and starts the NFQUEUE loop.
-- @tparam table auth_cfg  Auth configuration from cfg/filter.yml.
-- @treturn nil
run = (auth_cfg) ->
  auth_cfg or= {}

  -- Interface LAN (br0 or br)
  ifname = auth_cfg.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"

  https_port = auth_cfg.port or 33443

  local_ip = auth_cfg.captive_ip or os.getenv("CAPTIVE_IP") or "127.0.0.1"
  ok_sock, socket = pcall require, "socket"
  if ok_sock
    pcall ->
      u = socket.udp!
      pcall -> u\connect "8.8.8.8", 80
      ip, _ = u\getsockname!
      u\close!
      if ip and ip != "" and ip != "0.0.0.0"
        local_ip = ip

  host_part = local_ip\find(":", 1, true) and "[#{local_ip}]" or local_ip
  redirect_url = "https://#{host_part}:#{https_port}/"

  -- Open AF_PACKET socket (bridge mode)
  fd, err = open_raw_socket ifname
  unless fd
    log_error { action: "q2_socket_failed", err: err, ifname: ifname }
    return

  raw_fd = fd
  ifindex = tonumber ffi.C.if_nametoindex ifname
  if ifindex == 0
    log_error { action: "q2_ifindex_failed", ifname: ifname }
    return

  log_info {
    action:       "q2_worker_start"
    ifname:       ifname
    ifindex:      ifindex
    redirect_url: redirect_url
  }

  run_queue QUEUE_CAPTIVE, handle_syn

{ :run }
