-- src/worker_captive.moon
-- Worker captive : portail captif (bridge mode).
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
config = require "config"
parse: parse_eth, :new, :mac2s, :s2mac, proto: {:IP6, :IP4} = require "ipparse.l2.ethernet"
parse: parse_ip, proto: l3_proto, :ip2s = require "ipparse.l3.ip"
parse: parse_tcp = require "ipparse.l4.tcp"
{ :get_l2 } = require "nfq/ethernet"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_info, :log_warn, :log_error, :set_action_prefix } = require "log"
{ detect: detect_captive_ips } = require "captive_ips"
bridge_raw = require "bridge_raw"
{ :flags } = require "ipparse.l4.tcp"
{ :SYN, :ACK, :FIN, :PSH } = flags
mac_learner_ipc = require "mac_learner_ipc"
{ :user_for_mac, :enrich_session_ip } = require "auth.sessions"
-- Chargement conditionnel : libnftables n'est pas disponible en dehors du routeur
_nft_ok, _nft_sess = pcall require, "auth.nft_sessions"

-- ── TCP helper functions (ipparse for parsing and serialization) ──

PROTO_TCP   = l3_proto.TCP
PROTO_UDP   = l3_proto.UDP

-- Parse TCP SYN from NFQUEUE payload (bridge mode).
-- captive receives IP-only packets (no Ethernet header).
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
open_raw_socket = (ifname) -> bridge_raw.open_socket ifname

send_frame = (fd, frame, ifindex) -> bridge_raw.send fd, frame, ifindex

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
    log_warn -> { action: "parse_failed", queue: 2, len: payload_len, err: "parse_syn returned nil" }
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

  user = user_for_mac client_mac_str, client_ip_str, config.auth.sessions_file

  -- Si la MAC est déjà authentifiée (ex. rotation d'adresse IPv6 temporaire),
  -- ajouter la nouvelle IP dans les sets nft et retourner sans rediriger.
  if user
    ttl = (config.auth and config.auth.idle_timeout) or 120
    if _nft_ok and _nft_sess
      _nft_sess.add_authenticated client_ip_str, ttl
      _nft_sess.add_authenticated_mac client_mac_str, ttl
    enrich_session_ip client_mac_str, client_ip_str, config.auth.sessions_file
    log_info -> {
      action: "captive_skip_authenticated"
      ip:     client_ip_str
      mac:    client_mac_str
      user:   user
    }
    return NF_DROP

  send = (f) ->
    res = send_frame raw_fd, f, ifindex
    unless res
      log_warn -> { action: "frame_send_error", queue: 2, ip: client_ip_str, user: user, err: "send_frame returned false" }
    res

  url = custom_redirect_url or (if ip.version == 6
    redirect_url6 or redirect_url4
  else
    redirect_url4 or redirect_url6)

  unless url
    log_warn -> { action: "no_redirect_url", queue: 2, ip: client_ip_str, version: ip.version, user: user }
    return NF_DROP

  ok, err = pcall ->
    f1, f2, f3 = build_response_frames eth, ip, tcp, url
    log_info -> { action: "sending_frames", queue: 2, ip: client_ip_str, frames: 3, url: url, user: user }
    send f1
    send f2
    send f3

  if ok
    fields = {
      action:  "redirect_captive"
      queue:   2
      ip:      client_ip_str
      sport:   tcp.spt
      mac:     mac2s l2.mac_raw
      url:     url
      user:    user
    }
    if l2.mac_src and l2.mac_src != "unknown"
      fields.mac = l2.mac_src
    log_info -> fields
  else
    log_warn -> { action: "send_failed", queue: 2, err: "#{err}", ip: client_ip_str, user: user }

  NF_DROP



-- ── Point d'entrée ───────────────────────────────────────────────
--- Start the captive captive portal worker.
-- Opens the AF_PACKET socket (SOCK_RAW) and starts the NFQUEUE loop.
-- @tparam table auth_cfg  Auth configuration from runtime config.
-- @treturn nil
run = (queue_num, auth_cfg) ->
  set_action_prefix "captive_"
  auth_cfg or= {}

  -- Interface LAN (br0 or br)
  ifname = auth_cfg.bridge_ifname or "br0"

  https_port = auth_cfg.port or 33443

  -- URL de redirection personnalisée (optionnelle)
  -- Si spécifiée, elle est utilisée pour IPv4 et IPv6 (custom_redirect_url a
  -- la priorité dans handle_syn ; local_ip4/6 servent de fallback uniquement).
  custom_redirect_url = auth_cfg.redirect_url

  -- Détection des IPs du portail captif (config explicite, env, auto-détection).
  -- captive_ips.detect couvre: captive_ip4/6, CAPTIVE_IP4/6, ip addr show, socket.connect.
  local_ip4, local_ip6 = detect_captive_ips auth_cfg

  -- Build IPv4 redirect URL
  if local_ip4
    redirect_url4 = "https://#{local_ip4}:#{https_port}/"
  else
    log_warn -> { action: "no_ipv4", msg: "No IPv4 captive IP configured" }

  -- Build IPv6 redirect URL (wrap in brackets for URL)
  if local_ip6
    redirect_url6 = "https://[#{local_ip6}]:#{https_port}/"
  else
    log_warn -> { action: "no_ipv6", msg: "No IPv6 captive IP configured" }

  -- Open AF_PACKET socket (bridge mode)
  fd, err = open_raw_socket ifname
  unless fd
    log_error -> { action: "socket_failed", err: err, ifname: ifname }
    return

  raw_fd = fd
  ifindex = tonumber ffi.C.if_nametoindex ifname
  if ifindex == 0
    errno = tonumber(ffi.C.__errno_location()[0])
    log_error -> { action: "ifindex_failed", ifname: ifname, errno: errno }
    return

  -- Lire le MAC du bridge une seule fois (évite un open sysfs par SYN TCP)
  _bridge_mac = bridge_raw.read_mac ifname

  log_info -> {
    action: "worker_start"
    :ifname
    :ifindex
    custom_url: custom_redirect_url or "auto"
    redirect_url4: redirect_url4 or "not configured"
    redirect_url6: redirect_url6 or "not configured"
  }

  run_queue tonumber(queue_num), handle_syn

{ :run, :parse_syn, :build_response_frames }
