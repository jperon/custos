-- src/worker_q2.moon
-- Worker Q2 : portail captif (bridge et routeur).
--
-- Reçoit les TCP SYN vers le port 80 non autorisés (NFQUEUE 2).
-- Pour chaque SYN :
--   1. Parse le payload (trame Ethernet complète en mode bridge, paquet IP en mode routeur)
--   2. Forge et envoie via AF_PACKET :
--        a. SYN-ACK
--        b. ACK + HTTP/1.1 302 Found → https://<filtre>:33443/
--        c. FIN-ACK
--   3. Verdict NF_DROP sur le SYN original
--   4. Log structuré
--
-- Mode bridge (NFQ_BRIDGE_MODE=1) : AF_PACKET SOCK_RAW, construit la trame Ethernet.
-- Mode routeur (NFQ_BRIDGE_MODE=0) : AF_PACKET SOCK_DGRAM, le kernel gère le L2.

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :QUEUE_CAPTIVE, :NFQ_BRIDGE_MODE } = require "config"
{ :parse_syn, :parse_syn_ip, :build_response_frames
  :open_raw_socket, :send_frame
  :open_dgram_socket, :send_packet } = require "parse/tcp"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_info, :log_warn, :log_error } = require "log"

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

  syn = if NFQ_BRIDGE_MODE then parse_syn(raw) else parse_syn_ip(raw)
  unless syn
    log_warn { action: "q2_parse_failed", len: payload_len }
    return NF_DROP

  send = if NFQ_BRIDGE_MODE
    (f) -> send_frame raw_fd, f, ifindex
  else
    (f) -> send_packet raw_fd, f, ifindex

  ok, err = pcall ->
    f1, f2, f3 = build_response_frames syn, redirect_url, NFQ_BRIDGE_MODE
    send f1
    send f2
    send f3

  if ok
    fields = {
      action:  "captive_redirect_q2"
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
    log_warn { action: "q2_send_failed", err: tostring err, ip: syn.ip_src }

  NF_DROP


-- ── Point d'entrée ───────────────────────────────────────────────
--- Start the Q2 captive portal worker.
-- Opens the AF_PACKET socket (SOCK_RAW in bridge mode, SOCK_DGRAM in router mode)
-- and starts the NFQUEUE loop.
-- @tparam table auth_cfg  Auth configuration from cfg/filter.yml.
-- @treturn nil
run = (auth_cfg) ->
  auth_cfg = auth_cfg or {}

  -- Interface LAN (bridge mode: br0 or br; router mode: eth0/br-lan etc.)
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

  -- Open socket : SOCK_RAW en mode bridge, SOCK_DGRAM en mode routeur.
  open_fn = if NFQ_BRIDGE_MODE then open_raw_socket else open_dgram_socket
  fd, err = open_fn ifname
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
