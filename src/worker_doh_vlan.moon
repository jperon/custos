-- src/worker_doh_vlan.moon
-- Worker NFQUEUE pour la détection du VLAN des clients DoH.
--
-- Le worker DoH écoute sur un port TCP/TLS local et n'intercepte pas via
-- NFQUEUE : il ne voit donc pas le tag 802.1Q. Une chaîne input bridge route
-- les paquets destinés au port DoH vers cette file ; on y lit le VLAN (recopié
-- dans le mark par nft, via nfq_get_nfmark) et l'IP source, puis on transmet
-- l'association IP→VLAN au mac_learner (store interrogé par le worker DoH via
-- get_vlan). On renvoie TOUJOURS NF_ACCEPT : le filtrage du flux DoH reste le
-- rôle du serveur DoH lui-même.
--
-- L'état « untagged » (vlan == 0) est apprEND explicitement (et non ignoré) :
-- il doit écraser une éventuelle entrée VLAN stale, sans quoi un client
-- usurpant IP+MAC en untagged hériterait du VLAN d'un appareil légitime
-- (cf. AGENTS.md « from_vlan en DoH », anti-spoofing).

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :run_queue, :NF_ACCEPT } = require "nfq_loop"
{ :get_l2 } = require "nfq/ethernet"
{ :log_info, :log_warn, :log_debug, :set_action_prefix } = require "log"
{ :get_mac } = require "mac_learner_ipc"

ipparse_ip = require "ipparse.l3.ip"

-- fd d'écriture du pipe IPC vers le mac_learner (vlan_learn)
ipc_wfd = nil

--- Encode l'association IP→VLAN au format pipe vlan_learn (fonction pure).
-- Format : ip16 (16 octets) + vlan uint16 big-endian (2 octets) = 18 octets.
-- IPv4 paddée avec 12 zéros pour tenir dans le slot 16 octets.
-- @tparam number ip_version Version IP (4 ou 6)
-- @tparam string ip_raw Adresse IP brute (4 octets IPv4 ou 16 octets IPv6)
-- @tparam number vlan VLAN ID (0 = untagged)
-- @treturn string|nil Message de 18 octets, ou nil si entrée invalide
encode_vlan_msg = (ip_version, ip_raw, vlan) ->
  return nil unless ip_raw
  vlan = vlan or 0
  ip16 = if ip_version == 4
    return nil unless #ip_raw >= 4
    ip_raw\sub(1, 4) .. string.rep("\0", 12)
  else
    return nil unless #ip_raw >= 16
    ip_raw\sub 1, 16
  ip16 .. string.char(math.floor(vlan / 256) % 256, vlan % 256)

--- Envoie l'association IP→VLAN au mac_learner via le pipe vlan_learn.
-- @tparam number ip_version Version IP (4 ou 6)
-- @tparam string ip_raw Adresse IP brute (4 octets IPv4 ou 16 octets IPv6)
-- @tparam number vlan VLAN ID (0 = untagged)
-- @treturn boolean true si l'écriture a réussi
send_vlan_learn = (ip_version, ip_raw, vlan) ->
  return false unless ipc_wfd and ipc_wfd >= 0
  msg = encode_vlan_msg ip_version, ip_raw, vlan
  return false unless msg
  n = libc.write ipc_wfd, msg, 18
  n == 18

--- Décide si une observation untagged (vlan 0) doit être apprise (fonction pure).
-- En topologie routée, la SYN DoH d'un client tagué transite par le hook forward
-- (taguée, apprise par ailleurs) PUIS revient via la boucle routée untagged sur
-- l'IP du filtre : cette boucle a pour MAC source la passerelle, pas le client.
-- On ne l'apprend donc PAS (sinon elle écraserait le VLAN tagué fraîchement appris).
-- En revanche un vrai client untagged adjacent — ou un usurpateur IP+MAC — présente
-- la MAC connue de l'IP : on apprend (anti-spoofing préservé).
-- Fallback : si la MAC connue est inconnue/nil, on apprend (ne pas laisser stale).
-- @tparam string|nil frame_mac MAC source L2 de la trame (mac2s, minuscule)
-- @tparam string|nil known_mac MAC connue de l'IP (get_mac : "aa:.." ou "unknown")
-- @treturn boolean true si l'observation untagged doit être apprise
should_learn_untagged = (frame_mac, known_mac) ->
  return true unless known_mac and known_mac ~= "" and known_mac ~= "unknown"
  return true unless frame_mac and frame_mac ~= "" and frame_mac ~= "unknown"
  frame_mac == known_mac

--- Callback principal pour la file NFQUEUE (détection VLAN DoH).
-- Extrait le VLAN (mark) et l'IP source, transmet au mac_learner, accepte.
-- @tparam cdata qh_ptr Pointeur vers nfq_q_handle
-- @tparam cdata nfad Métadonnées du paquet
-- @tparam number pkt_id ID du paquet
-- @treturn number NF_ACCEPT (toujours)
handle_packet = (qh_ptr, nfad, pkt_id) ->
  l2 = get_l2 nfad
  -- vlan == 0 (untagged) est volontairement conservé : voir entête de module.
  vlan = (l2 and l2.vlan) or 0

  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  if payload_len <= 0
    log_warn -> { action: "no_payload", pkt_id: pkt_id, payload_len: payload_len }
    return NF_ACCEPT

  raw = ffi.string payload_ptr[0], payload_len
  ip, err = ipparse_ip.parse raw, 1
  unless ip
    log_debug -> { action: "parse_failed", pkt_id: pkt_id, err: err }
    return NF_ACCEPT

  if ip.src
    -- Gating anti-boucle-routée pour les observations untagged (vlan 0) :
    -- n'apprendre que si la trame émane bien de l'IP (MAC adjacente), pas de la
    -- passerelle (cf. should_learn_untagged + AGENTS.md « from_vlan en DoH »).
    if vlan == 0
      frame_mac = l2 and l2.mac_src
      ip_str = ipparse_ip.ip2s ip.src
      known_mac = ip_str and get_mac ip_str
      unless should_learn_untagged frame_mac, known_mac
        log_debug -> { action: "untagged_skip_nonadjacent", pkt_id: pkt_id, frame_mac: frame_mac or "unknown", known_mac: known_mac or "unknown" }
        return NF_ACCEPT
    ok = send_vlan_learn ip.version, ip.src, vlan
    unless ok
      log_warn -> { action: "ipc_failed", pkt_id: pkt_id, ip_version: ip.version }
    log_debug -> { action: "vlan_learned", pkt_id: pkt_id, vlan: vlan }

  NF_ACCEPT

--- Point d'entrée du worker.
-- @tparam number queue_num Numéro de la file NFQUEUE
-- @tparam number wfd Descripteur d'écriture du pipe vlan_learn vers le mac_learner
run = (queue_num, wfd) ->
  set_action_prefix "doh_vlan_"
  ipc_wfd = wfd
  log_info -> { action: "starting", queue: queue_num, ipc_fd: wfd }
  run_queue tonumber(queue_num), handle_packet

{ :run, :handle_packet, :send_vlan_learn, :encode_vlan_msg, :should_learn_untagged }
