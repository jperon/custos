-- src/workers/worker_auth_queue.moon
-- Worker NFQUEUE pour l'authentification captive sur port 33443.
-- Extrait la MAC source (L2) et l'IP source (L3), envoie au serveur auth via pipe IPC.

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :get_l2 } = require "nfq/ethernet"
{ :log_info, :log_warn, :log_error, :log_debug, :set_action_prefix } = require "log"

-- Import ipparse for L3 IP parsing
ipparse_ip = require "ipparse.l3.ip"

-- fd d'écriture du pipe IPC vers le serveur d'authentification
ipc_wfd = nil

--- Envoie les informations de connexion au serveur d'authentification.
-- Format binaire : ip16 (16 octets) + mac6 (6 octets) = 22 octets.
-- IPv4 addresses padded with 12 zeros to fit 16-byte format.
-- @tparam number ip_version IP version (4 or 6)
-- @tparam string ip_raw Adresse IP brute (4 octets IPv4 ou 16 octets IPv6)
-- @tparam string mac_raw Adresse MAC brute (6 octets)
-- @treturn boolean true si l'écriture a réussi
send_to_auth_server = (ip_version, ip_raw, mac_raw) ->
  return false unless ipc_wfd and ipc_wfd >= 0
  return false unless ip_raw and mac_raw and #mac_raw == 6

  msg = ffi.new "uint8_t[22]"

  if ip_version == 4
    -- IPv4: pad with 12 zeros to fill 16-byte slot
    for i = 1, 4
      msg[i - 1] = ip_raw\byte i
  else
    -- IPv6: direct copy
    for i = 1, 16
      msg[i - 1] = ip_raw\byte i

  -- MAC at offset 16
  for i = 1, 6
    msg[16 + i - 1] = mac_raw\byte i

  n = libc.write ipc_wfd, msg, 22
  return n == 22

--- Callback principal pour la queue NFQUEUE (authentification).
-- Extrait MAC source (L2) et IP source (L3), envoie au serveur auth.
-- @tparam cdata qh_ptr Pointeur vers nfq_q_handle
-- @tparam cdata nfad Métadonnées du paquet
-- @tparam number pkt_id ID du paquet
-- @treturn number NF_ACCEPT ou NF_DROP
handle_auth_packet = (qh_ptr, nfad, pkt_id) ->
  log_debug { action: "callback", pkt_id: pkt_id }

  -- 1. Extraire les infos L2 (MAC source)
  l2 = get_l2 nfad
  unless l2
    log_warn { action: "no_l2", pkt_id: pkt_id }
    return NF_ACCEPT

  -- 2. Extraire les infos L3 (IP source)
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  if payload_len <= 0
    log_warn { action: "no_payload", pkt_id: pkt_id, payload_len: payload_len }
    return NF_DROP

  raw = ffi.string payload_ptr[0], payload_len
  log_debug { action: "payload_len", len: payload_len }

  -- Parse IP header with ipparse (1-based offset)
  ip, err = ipparse_ip.parse raw, 1
  unless ip
    log_debug { action: "parse_failed", pkt_id: pkt_id, err: err }
    return NF_ACCEPT

  ip_raw = ip.src
  mac_raw = l2.mac_raw
  unless ip_raw and mac_raw
    log_warn { action: "missing_info", pkt_id: pkt_id, has_ip: ip_raw ~= nil, has_mac: mac_raw ~= nil }
    return NF_ACCEPT

  -- 3. Envoyer les infos au serveur d'authentification via IPC
  ok = send_to_auth_server ip.version, ip_raw, mac_raw
  unless ok
    log_warn { action: "ipc_failed", pkt_id: pkt_id, ip_version: ip.version }

  -- 4. Toujours accepter le paquet : c'est au serveur HTTPS de décider du sort de la connexion
  log_info { action: "processed", pkt_id: pkt_id }
  NF_ACCEPT

--- Point d'entrée du worker.
-- @tparam number queue_num Numéro de la queue
-- @tparam number wfd Descripteur d'écriture du pipe IPC vers le serveur
run = (queue_num, wfd) ->
  set_action_prefix "auth_queue_"
  ipc_wfd = wfd
  log_info { action: "starting", queue: queue_num, ipc_fd: wfd }
  run_queue tonumber(queue_num), handle_auth_packet

{ :run }
