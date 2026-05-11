-- src/worker_sip.moon
-- Worker NFQUEUE pour la signalisation SIP et STUN/ICE.
--
-- Rôle : toujours NF_ACCEPT le trafic SIP/STUN, et insérer dynamiquement
-- les IPs media (extraites du SDP) et les IPs proxy/STUN dans mac4/mac6_allowed,
-- de manière cohérente avec l'architecture DNS-centric de Custos.
--
-- Placement nft : après les whitelists DNS, avant ct state established,related.
-- Les paquets déjà whitelistés ne passent pas par cette queue.
--
-- v1 : UDP SIP complet + TCP best-effort (pas de réassemblage).
-- Limites v1 :
--   - SIPS/TLS (port 5061) : accepté sans parsing.
--   - TCP SIP fragmenté : SDP absent si > 1 segment.

{ :ffi, :libnfq } = require "ffi_defs"
{ :run_queue, :NF_ACCEPT } = require "nfq_loop"
{ :get_l2 } = require "nfq/ethernet"
{ :log_info, :log_warn, :log_debug, :set_action_prefix } = require "log"

ipparse_ip  = require "ipparse.l3.ip"
ipparse_udp = require "ipparse.l4.udp"
ipparse_tcp = require "ipparse.l4.tcp"
sip_parser  = require "sip.parser"

-- Module-level TTL, set during run().
sip_ttl = nil

-- ip4/ip6 → mac cache built from outbound SIP (phone → proxy).
-- Used to find phone_mac when parsing inbound responses.
ip_to_mac   = {}
IP_MAC_MAX  = 256

-- ── Helpers ───────────────────────────────────────────────────────────────────

--- Convert raw binary IP bytes to dotted/colon notation.
-- @tparam number version  IP version (4 or 6)
-- @tparam string raw      Raw IP bytes (4 or 16 bytes)
-- @treturn string|nil
format_ip = (version, raw) ->
  return nil unless raw
  if version == 4
    b1, b2, b3, b4 = raw\byte 1, 4
    return nil unless b1 and b4
    string.format "%d.%d.%d.%d", b1, b2, b3, b4
  elseif version == 6
    ok, s = pcall -> require("ipparse.l3.ip6").ip62s raw
    return s if ok and s
    nil

--- Record an ip → mac mapping for later reverse lookups.
-- Evicts the oldest entry once the cache is full.
-- @tparam string ip   IP address string
-- @tparam string mac  MAC address string
cache_ip_to_mac = (ip, mac) ->
  return unless ip and mac and mac != "unknown"
  return if ip_to_mac[ip]  -- already known
  count = 0
  for _ in pairs ip_to_mac
    count += 1
  if count >= IP_MAC_MAX
    first_k = next ip_to_mac
    ip_to_mac[first_k] = nil if first_k
  ip_to_mac[ip] = mac

--- Insert {mac . ip} into mac4_allowed or mac6_allowed and wait for ACK.
-- @tparam string mac     Source MAC address
-- @tparam string ip      Destination IP address
-- @tparam string family  "ip4" or "ip6"
-- @tparam string reason  Log label (used as nft correlation string)
allow_mac_ip = (mac, ip, family, reason) ->
  return unless mac and mac != "unknown" and ip and family
  nft_q = require "nft_queue"
  ok = if family == "ip6"
    nft_q.add_mac6 mac, ip, nil, sip_ttl, reason
  else
    nft_q.add_mac4 mac, ip, nil, sip_ttl, reason
  if ok
    pending = nft_q.get_last_seq!
    nft_q.wait_ack pending, reason if pending
  ok

--- Insert {ip_src . ip_dst} into ip4_allowed or ip6_allowed (fire-and-forget).
-- Used to whitelist a server that replies from a different source IP than the
-- one the client sent to (e.g. IPBX responding from its nearest VLAN interface).
-- No wait_ack: this covers future packets, not the current one.
-- @tparam string ip_src  Server/IPBX source IP
-- @tparam string ip_dst  Phone/client destination IP
-- @tparam string family  "ip4" or "ip6"
-- @tparam string reason  Log label
allow_ip_pair = (ip_src, ip_dst, family, reason) ->
  return unless ip_src and ip_dst and family
  nft_q = require "nft_queue"
  if family == "ip6"
    nft_q.add_ip6 ip_src, ip_dst, nil, sip_ttl, reason
  else
    nft_q.add_ip4 ip_src, ip_dst, nil, sip_ttl, reason

-- ── Packet handler ────────────────────────────────────────────────────────────

handle_packet = (qh_ptr, nfad, pkt_id) ->
  -- L2: source MAC.
  l2  = get_l2 nfad
  mac = l2.mac_src

  -- L3: IP header.
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  return NF_ACCEPT if payload_len <= 0

  raw = ffi.string payload_ptr[0], payload_len
  ip, ip_err = ipparse_ip.parse raw, 1
  unless ip
    log_debug { action: "ip_parse_failed", pkt_id: pkt_id, err: ip_err or "" }
    return NF_ACCEPT

  ip_version = ip.version
  ip_src_str = format_ip ip_version, ip.src
  ip_dst_str = format_ip ip_version, ip.dst
  ip_family  = if ip_version == 6 then "ip6" else "ip4"

  -- L4: UDP or TCP.
  sport, dport, l7_payload = nil, nil, nil

  if ip.protocol == 17  -- UDP
    ok_udp, udp = pcall -> ipparse_udp.parse raw, ip.data_off
    if ok_udp and udp
      sport = udp.spt
      dport = udp.dpt
      l7_payload = raw\sub udp.data_off if udp.data_off and udp.data_off <= #raw

  elseif ip.protocol == 6  -- TCP
    ok_tcp, tcp = pcall -> ipparse_tcp.parse raw, ip.data_off
    if ok_tcp and tcp
      sport = tcp.spt
      dport = tcp.dpt
      l7_payload = raw\sub tcp.data_off if tcp.data_off and tcp.data_off <= #raw

  return NF_ACCEPT unless sport and dport

  -- ── STUN (UDP dport 3478) ─────────────────────────────────────────────────
  if ip.protocol == 17 and dport == 3478
    if ip_dst_str and mac != "unknown"
      allow_mac_ip mac, ip_dst_str, ip_family, "sip_stun"
      log_debug { action: "stun_ip_added", mac: mac, ip: ip_dst_str }
    return NF_ACCEPT

  -- ── STUN responses (UDP sport 3478) ──────────────────────────────────────
  -- The STUN server may reply from a different source IP than the one the
  -- phone sent to (e.g. router uses its nearest interface), breaking conntrack.
  -- The nft rule `sport 3478 queue num N bypass` routes these here so we can
  -- NF_ACCEPT them explicitly instead of falling through to the reject queue.
  -- We also learn the actual response IP and add it to ip4/ip6_allowed so that
  -- future RTP media from that same IP to this phone is also accepted.
  if ip.protocol == 17 and sport == 3478
    if ip_src_str and ip_dst_str
      allow_ip_pair ip_src_str, ip_dst_str, ip_family, "sip_rtp_return"
    log_debug { action: "stun_response_accepted", ip: ip_src_str, dst: ip_dst_str }
    return NF_ACCEPT

  -- ── SIP/TLS (port 5061) : accept without parsing ─────────────────────────
  if dport == 5061 or sport == 5061
    return NF_ACCEPT

  -- ── SIP/clear (port 5060) ─────────────────────────────────────────────────
  outbound = (dport == 5060)  -- phone → proxy
  inbound  = (sport == 5060)  -- proxy → phone
  return NF_ACCEPT unless outbound or inbound

  -- When sport=dport=5060 both flags are set. Resolve the ambiguity by
  -- checking the ip_to_mac cache: if the destination IP is a cached phone,
  -- the packet is an inbound response (183, 200 OK, etc.); otherwise the
  -- source is the phone and it is an outbound request (INVITE, REGISTER…).
  if outbound and inbound
    if ip_to_mac[ip_dst_str]
      outbound = false
    else
      inbound = false

  -- Outbound: whitelist the proxy IP + cache phone MAC.
  if outbound and ip_dst_str and mac != "unknown"
    allow_mac_ip mac, ip_dst_str, ip_family, "sip_signal"
    cache_ip_to_mac ip_src_str, mac if ip_src_str

  -- Parse SIP to extract SDP media IPs.
  return NF_ACCEPT unless l7_payload and #l7_payload > 4

  msg = sip_parser.parse l7_payload
  return NF_ACCEPT unless msg and msg.sdp_ips and #msg.sdp_ips > 0

  -- Determine which MAC to use for SDP IP insertion:
  --   outbound → mac_src IS the phone's MAC
  --   inbound  → look up phone MAC from reverse cache (ip_dst = phone IP)
  target_mac = nil
  if outbound
    target_mac = mac
  elseif inbound
    target_mac = ip_to_mac[ip_dst_str] if ip_dst_str
    unless target_mac
      log_debug {
        action: "sip_no_mac_for_dst"
        ip_dst: ip_dst_str or "unknown"
      }
      return NF_ACCEPT

  for entry in *msg.sdp_ips
    allow_mac_ip target_mac, entry.ip, entry.family, "sip_media"
    -- For inbound (proxy→phone), also whitelist the reverse direction so the
    -- media server can send RTP to the phone even if it uses a different source
    -- IP than the one the SDP advertises.
    if inbound and ip_dst_str
      allow_ip_pair entry.ip, ip_dst_str, entry.family, "sip_media_return"
    log_debug {
      action:      "sip_media_ip_added"
      mac:         target_mac
      media_ip:    entry.ip
      family:      entry.family
      direction:   if inbound then "inbound" else "outbound"
      cseq_method: msg.cseq_method or ""
      sip_status:  tostring(msg.status_code or "")
      sip_method:  msg.method or ""
    }

  NF_ACCEPT

-- ── Entry point ───────────────────────────────────────────────────────────────

--- Start the SIP/STUN worker.
-- Blocks in the NFQUEUE loop until the process exits.
-- @tparam number queue_num  NFQUEUE number
-- @tparam table  fds        { nft_wfd, ack_rfd, worker_idx }
run = (queue_num, fds) ->
  set_action_prefix "sip_"
  cfg  = require "config"
  sip_ttl = (cfg.nft and cfg.nft.sip_session_ttl) or
            (cfg.nft and cfg.nft.ip_timeout) or "5m"
  if type(fds) == "table"
    nft_q = require "nft_queue"
    nft_q.set_wfd     fds.nft_wfd                   if fds.nft_wfd
    nft_q.set_ack_rfd fds.ack_rfd, fds.worker_idx   if fds.ack_rfd and fds.worker_idx != nil
  log_info { action: "worker_sip_starting", queue: queue_num, ttl: sip_ttl }
  run_queue tonumber(queue_num), handle_packet

{ :run }
