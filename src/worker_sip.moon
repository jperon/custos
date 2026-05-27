-- src/worker_sip.moon
--- Worker NFQUEUE pour la signalisation SIP et STUN/ICE.
---
--- Rôle : toujours NF_ACCEPT le trafic SIP/STUN, et insérer dynamiquement
-- les IPs media (extraites du SDP) et les IPs proxy/STUN dans les sets par règle,
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
ok_mac_ipc, mac_ipc = pcall -> require "mac_learner_ipc"

-- Module-level TTL, set during run().
sip_ttl = nil

-- ip4/ip6 → mac cache built from outbound SIP (phone → proxy).
-- Used to find phone_mac when parsing inbound responses.
ip_to_mac   = {}
IP_MAC_MAX  = 256

-- ── Helpers ───────────────────────────────────────────────────────────────────

--- Convert raw binary IP bytes to dotted/colon notation.
-- Utilise ip2s pour garantir la cohérence avec le reste du codebase.
-- @tparam number version  IP version (4 or 6)
-- @tparam string raw      Raw IP bytes (4 or 16 bytes)
-- @treturn string|nil
format_ip = (version, raw) ->
  return nil unless raw
  ip2s = require("ipparse.l3.ip").ip2s
  if version == 4
    ip2s raw\sub 1, 4
  elseif version == 6
    ip2s raw
  else
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

known_phone_mac = (ip) ->
  return nil unless ip
  ip_to_mac[ip]

is_lan_ip = (ip) ->
  return false unless ip
  return true if ip\match("^10%.")
  return true if ip\match("^192%.168%.")
  if b = tonumber ip\match("^172%.(%d+)%.")
    return true if b >= 16 and b <= 31
  return true if ip\match("^[Ff][CcDd][0-9a-fA-F:]*$")
  false

query_phone_mac = (ip) ->
  return nil unless is_lan_ip ip
  return nil unless ok_mac_ipc and mac_ipc and mac_ipc.get_mac and ip
  mac = mac_ipc.get_mac ip
  return nil unless mac and mac != "unknown"
  cache_ip_to_mac ip, mac
  mac

resolve_outbound_mac = (ip_src_str, packet_mac) ->
  mac = known_phone_mac ip_src_str
  return mac, "cache" if mac
  if is_lan_ip(ip_src_str) and packet_mac and packet_mac != "unknown"
    return packet_mac, "packet"
  mac = query_phone_mac ip_src_str
  return mac, "learner" if mac
  nil, "none"

classify_direction = (sport, dport, ip_src_str, ip_dst_str) ->
  outbound = (dport == 5060)
  inbound  = (sport == 5060)
  return false, false, false unless outbound or inbound

  -- sport=dport=5060: disambiguate with phone cache.
  if outbound and inbound
    if known_phone_mac ip_dst_str
      outbound = false
    else
      inbound = false
  -- dport=5060 only: can still be inbound when provider uses random source port.
  elseif outbound and (not inbound) and known_phone_mac(ip_dst_str)
    outbound = false
    inbound = true
  -- sport=5060 only: symmetric safeguard (rare).
  elseif inbound and (not outbound) and known_phone_mac(ip_src_str)
    inbound = false
    outbound = true

  outbound, inbound, true

--- Insert {mac . ip} into per-rule sets and wait for ACK.
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

--- Insert an IP into sip_peers (or sip_peers6), fire-and-forget.
-- Called for every IP seen in a SIP dialog (phone, proxy, media server).
-- The nft rule `ip saddr @sip_peers ip daddr @sip_peers accept` then lets
-- RTP flow freely between any two known SIP peers (both directions).
-- @tparam string ip      IP address string
-- @tparam string family  "ip4" or "ip6"
-- @tparam string reason  Log label (correlation)
allow_sip_peer = (ip, family, reason) ->
  return unless ip and family
  nft_q = require "nft_queue"
  if family == "ip6"
    nft_q.add_sip6 ip, nil, sip_ttl, reason
  else
    nft_q.add_sip4 ip, nil, sip_ttl, reason

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
    log_debug -> { action: "ip_parse_failed", pkt_id: pkt_id, err: ip_err or "" }
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
      log_debug -> { action: "stun_ip_added", mac: mac, ip: ip_dst_str }
    return NF_ACCEPT

  -- ── STUN responses (UDP sport 3478) ──────────────────────────────────────
  -- The STUN server may reply from a different source IP than the one the
  -- phone sent to (e.g. router uses its nearest interface), breaking conntrack.
  -- The nft rule `sport 3478 queue num N bypass` routes these here so we can
  -- NF_ACCEPT them explicitly instead of falling through to the reject queue.
  -- We also learn the actual response IP and add it to per-rule sets so that
  -- future RTP media from that same IP to this phone is also accepted.
  if ip.protocol == 17 and sport == 3478
    if ip_src_str and ip_dst_str
      allow_sip_peer ip_src_str, ip_family, "stun_src"
      allow_sip_peer ip_dst_str, ip_family, "stun_dst"
    log_debug -> { action: "stun_response_accepted", ip: ip_src_str, dst: ip_dst_str }
    return NF_ACCEPT

  -- ── SIP/TLS (port 5061) : accept without parsing ─────────────────────────
  if dport == 5061 or sport == 5061
    return NF_ACCEPT

  -- ── SIP/clear (port 5060) ─────────────────────────────────────────────────
  outbound, inbound, is_sip = classify_direction sport, dport, ip_src_str, ip_dst_str
  return NF_ACCEPT unless is_sip
  outbound_mac = nil
  outbound_mac_src = "none"
  if outbound
    outbound_mac, outbound_mac_src = resolve_outbound_mac ip_src_str, mac
    log_debug -> {
      action: "sip_outbound_mac_selected"
      ip_src: ip_src_str or ""
      packet_mac: mac or ""
      selected_mac: outbound_mac or ""
      source: outbound_mac_src
    }

  -- Outbound: whitelist the proxy IP + cache phone MAC.
  if outbound and ip_dst_str and outbound_mac
    allow_mac_ip outbound_mac, ip_dst_str, ip_family, "sip_signal"
    cache_ip_to_mac ip_src_str, outbound_mac if ip_src_str and is_lan_ip(ip_src_str)

  -- Parse SIP payload.
  return NF_ACCEPT unless l7_payload and #l7_payload > 4

  msg = sip_parser.parse l7_payload
  return NF_ACCEPT unless msg

  -- Enregistrer les deux IPs du paquet SIP comme pairs connus.
  -- La règle nft `ip saddr @sip_peers ip daddr @sip_peers accept`
  -- autorisera ensuite le RTP entre ces IPs sans passer par les sets par règle.
  allow_sip_peer ip_src_str, ip_family, "sip_peer_src"
  allow_sip_peer ip_dst_str, ip_family, "sip_peer_dst"

  dst_phone_mac = known_phone_mac(ip_dst_str) or query_phone_mac(ip_dst_str)

  -- Parse SIP to extract SDP media IPs.
  return NF_ACCEPT unless msg and msg.sdp_ips and #msg.sdp_ips > 0

  -- Determine which MAC to use for SDP IP insertion:
  --   outbound → mac_src IS the phone's MAC
  --   inbound  → look up phone MAC from reverse cache (ip_dst = phone IP)
  target_mac = nil
  if outbound
    target_mac = outbound_mac
    unless target_mac
      log_debug -> {
        action: "sip_no_mac_for_src"
        ip_src: ip_src_str or "unknown"
      }
      return NF_ACCEPT
  elseif inbound
    target_mac = dst_phone_mac
    unless target_mac
      log_debug -> {
        action: "sip_no_mac_for_dst"
        ip_dst: ip_dst_str or "unknown"
      }
      return NF_ACCEPT

  for entry in *msg.sdp_ips
    -- Ajouter l'IP media dans sip_peers pour le passage RTP bidirectionnel.
    allow_sip_peer entry.ip, entry.family, "sip_media"
    -- Conserver l'entrée MAC pour l'outbound (téléphone → media server).
    allow_mac_ip target_mac, entry.ip, entry.family, "sip_media"
    log_debug -> {
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
  log_info -> { action: "worker_sip_starting", queue: queue_num, ttl: sip_ttl }
  run_queue tonumber(queue_num), handle_packet

{
  :run
  :classify_direction
  :resolve_outbound_mac
  remember_phone_ip: cache_ip_to_mac
}
