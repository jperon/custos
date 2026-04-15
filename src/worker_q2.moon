-- src/worker_q2.moon
-- Worker Q2 : portail captif en mode bridge.
--
-- Reçoit les TCP SYN vers le port 80 non autorisés (NFQUEUE 2).
-- Pour chaque SYN :
--   1. Parse la trame Ethernet complète (mode bridge : payload = trame L2 entière)
--   2. Forge et envoie via AF_PACKET :
--        a. SYN-ACK
--        b. ACK + HTTP/1.1 302 Found → https://<filtre>:33443/
--        c. FIN-ACK
--   3. Verdict NF_DROP sur le SYN original
--   4. Log structuré
--
-- Ce worker n'est lancé qu'en mode bridge (BRIDGE_MODE=1).
-- En mode routeur, le portail captif utilise le DNAT nftables existant.

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :QUEUE_CAPTIVE } = require "config"
{ :parse_syn, :build_response_frames, :open_raw_socket, :send_frame } = require "parse/tcp"
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

  syn = parse_syn raw
  unless syn
    log_warn { action: "q2_parse_failed", len: payload_len }
    return NF_DROP

  ok, err = pcall ->
    f1, f2, f3 = build_response_frames syn, redirect_url
    send_frame raw_fd, f1, ifindex
    send_frame raw_fd, f2, ifindex
    send_frame raw_fd, f3, ifindex

  if ok
    log_info {
      action:  "captive_redirect_q2"
      ip:      syn.ip_src
      sport:   syn.sport
      mac:     string.format "%02x:%02x:%02x:%02x:%02x:%02x",
                 syn.eth_src\byte(1), syn.eth_src\byte(2), syn.eth_src\byte(3),
                 syn.eth_src\byte(4), syn.eth_src\byte(5), syn.eth_src\byte(6)
      vlan:    tonumber(libnfq.nfq_get_nfmark nfad) or nil
      url:     redirect_url
    }
  else
    log_warn { action: "q2_send_failed", err: tostring err, ip: syn.ip_src }

  NF_DROP


-- ── Point d'entrée ───────────────────────────────────────────────
--- Start the Q2 captive portal worker (bridge mode only).
-- Opens the AF_PACKET socket and starts the NFQUEUE loop.
-- @tparam table auth_cfg  Auth configuration from cfg/filter.yml.
-- @treturn nil
run = (auth_cfg) ->
  auth_cfg = auth_cfg or {}

  -- Resolve the bridge interface name (default: "br").
  ifname = auth_cfg.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"

  -- Resolve the HTTPS port for the captive portal redirect.
  https_port = auth_cfg.port or 33443

  -- Detect the filter's IP on the bridge to build the redirect URL.
  -- Use luasocket if available, otherwise fall back to a configurable address.
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

  -- Open the AF_PACKET raw socket.
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
