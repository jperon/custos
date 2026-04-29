-- src/workers/worker_auth_queue.moon
-- Worker NFQUEUE hybride pour l'authentification captive.
-- Capture le trafic sur le port 33443, extrait l'adresse MAC (L2)
-- et l'adresse IP (L3), puis transmet ces infos au serveur HTTPS
-- via un pipe IPC avant d'accepter le paquet.

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :get_l2 } = require "parse/ethernet"
ndpi = require "parse/ndpi"
{ :log_info, :log_warn, :log_error, :log_debug } = require "log"

-- fd d'écriture du pipe IPC vers le serveur d'authentification
ipc_wfd = nil

--- Envoie les informations de connexion au serveur d'authentification.
-- Format binaire : ip16 (16 octets) + mac6 (6 octets) = 22 octets.
-- Identique au format utilisé par Q0 pour mac_learner.
-- @tparam string ip_raw Adresse IP brute (4 octets IPv4 ou 16 octets IPv6)
-- @tparam string mac_raw Adresse MAC brute (6 octets)
-- @treturn boolean true si l'écriture a réussi
send_to_auth_server = (ip_raw, mac_raw) ->
  return false unless ipc_wfd and ipc_wfd >= 0
  return false unless ip_raw and (#ip_raw == 4 or #ip_raw == 16)
  return false unless mac_raw and #mac_raw == 6

  msg = ffi.new "uint8_t[22]"

  if #ip_raw == 4
    for i = 1, 4
      msg[i - 1] = ip_raw\byte i
  else
    for i = 1, 16
      msg[i - 1] = ip_raw\byte i

  for i = 1, 6
    msg[15 + i] = mac_raw\byte i

  n = libc.write ipc_wfd, msg, 22
  return n == 22

--- Callback principal pour la queue NFQUEUE 4.
-- @tparam cdata qh_ptr Pointeur vers nfq_q_handle
-- @tparam cdata nfad Métadonnées du paquet
-- @tparam number pkt_id ID du paquet
-- @treturn number NF_ACCEPT ou NF_DROP
handle_auth_packet = (qh_ptr, nfad, pkt_id) ->
  -- 1. Extraire les infos L2 (MAC source)
  l2 = get_l2 nfad

  -- 2. Extraire les infos L3/L7 (IP source)
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  return NF_DROP if payload_len <= 0

  raw = ffi.string payload_ptr[0], payload_len
  pkt = ndpi.parse_packet raw
  unless pkt
    return NF_ACCEPT -- Laisser passer si on ne peut pas parser

  -- 3. Envoyer les infos au serveur d'authentification via IPC
  ip_raw = pkt.ip.src_ip_raw
  mac_raw = l2.mac_raw

  unless ip_raw and mac_raw
    log_warn { action: "auth_queue_missing_info", ip: pkt.ip.src_ip, mac: l2.mac_src }
    return NF_ACCEPT

  ok = send_to_auth_server ip_raw, mac_raw
  unless ok
    log_warn { action: "auth_queue_ipc_failed", ip: pkt.ip.src_ip, mac: l2.mac_src }

  -- 4. Toujours accepter le paquet : c'est au serveur HTTPS de décider du sort de la connexion
  log_debug { action: "auth_queue_accepted", ip: pkt.ip.src_ip, mac: l2.mac_src }
  NF_ACCEPT

--- Point d'entrée du worker.
-- @tparam number queue_num Numéro de la queue (4)
-- @tparam number wfd Descripteur d'écriture du pipe IPC vers le serveur
run = (queue_num, wfd) ->
  ipc_wfd = wfd
  ndpi.warmup!
  log_info { action: "auth_queue_starting", queue: queue_num, ipc_fd: wfd }
  run_queue tonumber(queue_num), handle_auth_packet
  ndpi.cleanup!

{ :run }
