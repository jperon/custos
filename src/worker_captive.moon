-- src/worker_q2.moon
-- Worker Q2 : portail captif (bridge mode).
--
-- Reçoit les TCP SYN vers le port 80 non autorisés (NFQUEUE 2).
-- Le payload NFQUEUE commence à l'en-tête IP (pas d'Ethernet).
-- Pour chaque SYN :
--   1. Parse IP + TCP
--   2. Forge et envoie via AF_PACKET/SOCK_RAW sur `br` (nécessaire :
--      NFQUEUE ne peut injecter qu'un seul paquet en remplacement, et
--      ne peut pas inverser la direction d'un paquet) :
--        a. SYN-ACK
--        b. ACK + HTTP/1.1 302 Found → https://<filtre>:33443/
--        c. FIN-ACK
--   3. Verdict NF_DROP sur le SYN original
--   4. Log structuré

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :AUTH_SESSIONS_FILE } = require "config"
parse: parse_eth, :new, :mac2s, :s2mac, proto: {:IP6, :IP4} = require "ipparse.l2.ethernet"
parse: parse_ip, proto: l3_proto, :ip2s = require "ipparse.l3.ip"
parse: parse_tcp = require "ipparse.l4.tcp"
{ :get_l2 } = require "parse/ethernet"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_info, :log_warn, :log_error } = require "log"
{ :flags } = require "ipparse.l4.tcp"
{ :SYN, :ACK, :FIN, :PSH } = flags
mac_learner_ipc = require "mac_learner_ipc"
{ :user_for_ip } = require "auth.sessions"

-- ── TCP helper functions (ipparse for parsing and serialization) ──

AF_PACKET   = 17
SOCK_RAW    = 3
ETH_P_ALL   = 0x0300  -- htons(0x0003)
PROTO_TCP   = l3_proto.TCP
PROTO_UDP   = l3_proto.UDP

-- Parse TCP SYN from NFQUEUE payload (bridge mode).
-- Q2 receives IP-only packets (no Ethernet header).
-- Returns the parsed IP and TCP objects (no Ethernet header).
parse_syn = (raw) ->
  -- Parse IP at offset 1 (Lua 1-based string indexing)
  ip, ip_off = parse_ip raw, 1
  return nil unless ip

  -- Parse TCP at the offset after IP header
  tcp, tcp_off = parse_tcp raw, ip.data_off
  return nil unless tcp

  ip, ip_off, tcp, tcp_off

-- Build Ethernet frames for TCP redirect using ipparse
-- Modifies parsed objects in-place (no cloning, no constructor overhead)
build_response_frames = (eth, ip, tcp, redirect_url) ->
  isn = math.random 0, 0x7FFFFFFF
  http_body = "HTTP/1.1 302 Found\r\nLocation: #{redirect_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  http_len  = #http_body

  their_seq_plus1 = (tcp.seq_n + 1) % 0x100000000

  -- Swap src/dst once (before frame building loop)
  tcp.spt, tcp.dpt = tcp.dpt, tcp.spt
  ip.src, ip.dst = ip.dst, ip.src
  eth.dst, eth.src = eth.src, eth.dst

  build_frame = (tcp_flags, payload_str, our_seq, their_ack) ->
    -- Modify TCP in-place
    tcp.seq_n = our_seq
    tcp.ack_n = their_ack
    tcp.flags = tcp_flags
    tcp.window = 65535
    tcp.urg_ptr = 0
    tcp.data = payload_str or ""

    -- Modify IP in-place
    ip.ttl or= 64
    if ip.version == 4
      ip.protocol = PROTO_TCP
    else
      ip.next_header = PROTO_TCP
    ip.data = tcp

    -- Modify Ethernet in-place
    if ip.version == 4
      eth.protocol = 0x0800
    else
      eth.protocol = 0x86DD
    eth.data = ip

    -- Serialize (checksums calculated automatically by ipparse pack methods)
    "#{eth}"

  syn_ack = build_frame (SYN + ACK), nil, isn, their_seq_plus1
  data    = build_frame (PSH + ACK), http_body, (isn + 1) % 0x100000000, their_seq_plus1
  fin_ack = build_frame (FIN + ACK), nil, (isn + 1 + http_len) % 0x100000000, their_seq_plus1

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

-- MAC du bridge, lu une seule fois au démarrage (binaire, 6 octets)
_bridge_mac = nil

-- URLs de redirection vers le portail captif HTTPS.
-- Construites depuis auth_cfg à l'initialisation (IPv4 et IPv6).
-- Si auth_cfg.redirect_url est spécifié, il est utilisé pour les deux versions.
redirect_url4 = nil
redirect_url6 = nil
custom_redirect_url = nil

-- ── Callback principal ───────────────────────────────────────────
--- Handle a TCP SYN/80 packet from NFQUEUE 2.
-- Parses the packet, forges a TCP 302 redirect response, and drops the SYN.
-- @tparam cdata  qh_ptr  nfq_q_handle pointer
-- @tparam cdata  nfad    nfq_data pointer
-- @tparam number pkt_id  NFQUEUE packet id
-- @treturn number NF_DROP always (response injected via AF_PACKET)
handle_syn = (qh_ptr, nfad, pkt_id) ->
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  return NF_DROP if payload_len <= 0

  raw = ffi.string payload_ptr[0], payload_len

  -- Extract L2 info from NFQUEUE metadata (MAC source via nfq_get_packet_hw)
  l2 = get_l2 nfad

  ip, ip_off, tcp, tcp_off = parse_syn(raw)
  unless ip
    log_warn { action: "q2_parse_failed", queue: 2, len: payload_len }
    return NF_DROP

  -- Use client MAC from NFQUEUE metadata (l2.mac_raw contains the source MAC from the packet)
  -- In bridge mode with IP-only packets, get_l2 uses nfq_get_packet_hw() which has the client MAC
  client_mac = l2.mac_raw if l2.mac_raw and l2.mac_raw != "\0\0\0\0\0\0"

  -- Create Ethernet header using ipparse's new function
  -- Note: build_response_frames swaps src/dst, so we set them in reverse:
  -- - eth.src = client MAC (becomes dst after swap)
  -- - eth.dst = bridge MAC (becomes src after swap)
  eth = new {
    src: client_mac or "\xFF\xFF\xFF\xFF\xFF\xFF"
    dst: _bridge_mac or "\0\0\0\0\0\0"
    protocol: ip.version == 4 and IP4 or IP6
  }
  eth_off = 1

  client_ip_str = ip2s ip.src
  client_mac_str = l2.mac_src
  if not client_mac_str or client_mac_str == "unknown"
    client_mac_str = mac_learner_ipc.get_mac client_ip_str

  user          = user_for_ip client_ip_str, AUTH_SESSIONS_FILE, client_mac_str

  send = (f) ->
    res = send_frame raw_fd, f, ifindex
    unless res
      log_warn { action: "q2_frame_send_error", queue: 2, ip: client_ip_str, user: user }
    res

  url = custom_redirect_url or (if ip.version == 6
    redirect_url6 or redirect_url4
  else
    redirect_url4 or redirect_url6)

  unless url
    log_warn { action: "q2_no_redirect_url", queue: 2, ip: client_ip_str, version: ip.version, user: user }
    return NF_DROP

  ok, err = pcall ->
    f1, f2, f3 = build_response_frames eth, ip, tcp, url
    log_info { action: "q2_sending_frames", queue: 2, ip: client_ip_str, frames: 3, url: url, user: user }
    send f1
    send f2
    send f3

  if ok
    fields = {
      action:  "captive_redirect_q2"
      queue:   2
      ip:      client_ip_str
      sport:   tcp.spt
      mac:     mac2s l2.mac_raw
      url:     url
      user:    user
    }
    if l2.mac_src and l2.mac_src != "unknown"
      fields.mac = l2.mac_src
    log_info fields
  else
    log_warn { action: "q2_send_failed", queue: 2, err: "#{err}", ip: client_ip_str, user: user }

  NF_DROP



-- ── Point d'entrée ───────────────────────────────────────────────
--- Start the Q2 captive portal worker.
-- Opens the AF_PACKET socket (SOCK_RAW) and starts the NFQUEUE loop.
-- @tparam table auth_cfg  Auth configuration from cfg/filter.yml.
-- @treturn nil
run = (queue_num, auth_cfg) ->
  auth_cfg or= {}

  -- Interface LAN (br0 or br)
  ifname = auth_cfg.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"

  https_port = auth_cfg.port or 33443

  -- URL de redirection personnalisée (optionnelle)
  -- Si spécifiée, elle est utilisée pour IPv4 et IPv6, ignorant captive_ip4/6
  custom_redirect_url = auth_cfg.redirect_url

  -- IPv4 captive IP (from config, env var, or auto-detect)
  -- Ignoré si redirect_url est spécifié
  local_ip4 = auth_cfg.captive_ip4 or os.getenv("CAPTIVE_IP4") unless custom_redirect_url
  local_ip6 = auth_cfg.captive_ip6 or os.getenv("CAPTIVE_IP6") unless custom_redirect_url

  -- Fallback to single captive_ip for backwards compatibility
  -- NOTE: do not default to 127.0.0.1 here — that prevents auto-detection.
  if not local_ip4 and not local_ip6
    local_ip = auth_cfg.captive_ip or os.getenv("CAPTIVE_IP")
    if local_ip
      if local_ip\find(":", 1, true)
        local_ip6 = local_ip
      else
        local_ip4 = local_ip

  -- Auto-detect local IPs if not specified
  ok_sock, socket = pcall require, "socket"
  if ok_sock
    pcall ->
      -- Prefer the IPv4 address configured on the bridge interface before
      -- falling back to the socket.connect heuristic (more deterministic).
      if not local_ip4
        ok, out = pcall ->
          fh = io.popen "ip -4 addr show dev #{ifname} scope global 2>/dev/null | awk '/inet/{print $2}' | head -1 | cut -d'/' -f1"
          return nil unless fh
          s = fh\read "*a"
          fh\close!
          s = s\gsub "%s+", ""
          s
        if ok and out and out != "" and out != "0.0.0.0"
          local_ip4 = out

      -- Fallback to socket method for IPv4 if interface read failed or returned nothing
      u = nil
      if not local_ip4
        ok_udp, u_or_err = pcall socket.udp
        u = u_or_err if ok_udp and u_or_err
        if u
          ok_conn, _ = pcall u.connect, u, "1.1.1.1", 80
          if ok_conn
            ok_get, ip = pcall u.getsockname, u
            if ok_get and ip and ip != "" and ip != "0.0.0.0"
              local_ip4 = ip

      u\close! if u

  -- Fallback: read IPv6 from bridge interface if auto-detection failed
  if not local_ip6
    bridge_ifname = auth_cfg.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"
    -- Try to get IPv6 address from ip command
    ok, ip = pcall ->
      f = io.popen "ip -6 addr show dev #{bridge_ifname} scope global 2>/dev/null | awk '/inet6/{print $2}' | head -1 | cut -d'/' -f1"
      if f
        addr = f\read "*a"
        f\close!
        -- Strip all whitespace (newlines, carriage returns, spaces)
        addr\gsub "%s+", ""
    if ok and ip and ip != "" and ip != "::"
      local_ip6 = ip
      log_info { action: "q2_ipv6_from_interface", ip: local_ip6, ifname: bridge_ifname }

  -- Build IPv4 redirect URL
  if local_ip4
    redirect_url4 = "https://#{local_ip4}:#{https_port}/"
  else
    log_warn { action: "q2_no_ipv4", msg: "No IPv4 captive IP configured" }

  -- Build IPv6 redirect URL (wrap in brackets for URL)
  if local_ip6
    redirect_url6 = "https://[#{local_ip6}]:#{https_port}/"
  else
    log_warn { action: "q2_no_ipv6", msg: "No IPv6 captive IP configured" }

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

  -- Lire le MAC du bridge une seule fois (évite un open sysfs par SYN TCP)
  do
    fh = io.open "/sys/class/net/#{ifname}/address", "r"
    if fh
      mac_str = fh\read("*a")\gsub "\n", ""
      fh\close!
      _bridge_mac = s2mac mac_str if mac_str and #mac_str > 0

  log_info {
    action: "q2_worker_start"
    :ifname
    :ifindex
    custom_url: custom_redirect_url or "auto"
    redirect_url4: redirect_url4 or "not configured"
    redirect_url6: redirect_url6 or "not configured"
  }

  run_queue tonumber(queue_num), handle_syn

{ :run }
