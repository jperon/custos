{ :ffi, :libc } = require "ffi_defs"
{ :log_warn, :log_debug } = require "log"
{ :NFT_FAMILY, :NFT_FAMILY6, :NFT_TABLE, :NFT_SET_IP4, :NFT_SET_IP6, :NFT_SET_MAC4, :NFT_SET_MAC6, :NFT_IP_TIMEOUT, :NFT_ACK_TIMEOUT_MS } = require "config"

PIPE_BUF_SAFE = 512
IPC_WRITE_RETRY_COUNT = 3
EAGAIN = 11
EWOULDBLOCK = 11
POLLIN = 1

-- Pipe d'envoi des insertions nft vers worker_nft.
pipe_wfd = nil
-- Pipe ACK dédié à ce worker (lecture) : worker_nft écrit 1 octet après chaque flush.
ack_rfd = nil
-- Index de ce worker dans le tableau ack_wfds[] de worker_nft.
worker_idx = nil
-- Compteur de séquence monotone (identifie chaque enqueue dans les logs).
-- Chaque worker repart de 0 au démarrage — pas besoin de coordination globale.
seq = 0
-- seq du dernier message effectivement enfilé dans le pipe (nil si rien depuis le dernier wait_ack).
last_enqueued_seq = nil

sleep_req = ffi.new "timespec_t[1]"
poll_fds  = ffi.new "struct pollfd[1]"
ack_buf   = ffi.new "uint8_t[1]"

set_wfd = (wfd) ->
  pipe_wfd = wfd

--- Configure le canal ACK pour ce worker.
-- Doit être appelé avant toute insertion dans les workers qui attendent l'ACK.
-- @tparam number rfd    fd de lecture du pipe ACK dédié à ce worker
-- @tparam number idx    index de ce worker dans le tableau ack_wfds[] de worker_nft
-- @treturn nil
set_ack_rfd = (rfd, idx) ->
  ack_rfd    = rfd
  worker_idx = idx

sleep_ms = (ms) ->
  sleep_req[0].tv_sec = math.floor ms / 1000
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  libc.nanosleep sleep_req, nil

write_line = (line) ->
  return false unless pipe_wfd
  return false if #line > PIPE_BUF_SAFE
  for i = 1, IPC_WRITE_RETRY_COUNT
    n = libc.write pipe_wfd, line, #line
    return true if n == #line
    errno_p = libc.__errno_location!
    errno = if errno_p then errno_p[0] else 0
    if errno != EAGAIN and errno != EWOULDBLOCK
      log_warn { action: "nft_queue_write_failed", fd: pipe_wfd, line: line, errno: errno }
      return false
    sleep_ms 10
  log_warn { action: "nft_queue_write_exhausted", fd: pipe_wfd, line: line }
  false

--- Enfile une insertion nft dans le pipe vers worker_nft.
-- Le message inclut worker_idx pour que worker_nft sache quel pipe ACK utiliser.
-- Format : "kind|key|ip|seq|worker_idx\n"
-- @tparam string kind  "ip4", "ip6", "mac4" ou "mac6"
-- @tparam string key   IP client (ip4/ip6) ou adresse MAC (mac4/mac6)
-- @tparam string ip    IP destination à insérer dans le set nft
-- @treturn boolean true si l'écriture dans le pipe a réussi
enqueue = (kind, key, ip) ->
  return false unless kind and key and ip
  seq += 1
  -- Inclure worker_idx seulement si un canal ACK est configuré.
  -- Les callers sans ACK (ex: anciens usages fire-and-forget) ont worker_idx = nil.
  line = if worker_idx
    "#{kind}|#{key}|#{ip}|#{seq}|#{worker_idx}\n"
  else
    "#{kind}|#{key}|#{ip}\n"
  ok = write_line line
  last_enqueued_seq = seq if ok
  ok

add_ip4  = (client_ip, ip_str) -> enqueue "ip4",  client_ip, ip_str
add_ip6  = (client_ip, ip_str) -> enqueue "ip6",  client_ip, ip_str
add_mac4 = (mac, ip_str)       -> enqueue "mac4", mac,       ip_str
add_mac6 = (mac, ip_str)       -> enqueue "mac6", mac,       ip_str

--- Retourne le seq du dernier message enfilé, puis le remet à nil.
-- Permet au caller de savoir s'il y a des insertions en attente d'ACK
-- et de passer le seq à wait_ack() pour le logging.
-- @treturn number|nil seq du dernier enqueue, ou nil si aucun enqueue depuis le dernier appel
get_last_seq = ->
  s = last_enqueued_seq
  last_enqueued_seq = nil
  s

--- Attend l'ACK de worker_nft confirmant que les insertions ont été flushées dans nftables.
-- Bloque au plus NFT_ACK_TIMEOUT_MS millisecondes (fail-open si dépassé).
-- N'est utile que si set_ack_rfd() a été appelé au préalable.
-- @tparam number   pending_seq  seq du dernier enqueue (pour le logging uniquement)
-- @treturn boolean true si ACK reçu, false si timeout (fail-open)
wait_ack = (pending_seq) ->
  return true unless ack_rfd
  timeout_ms = NFT_ACK_TIMEOUT_MS or 150
  poll_fds[0].fd      = ack_rfd
  poll_fds[0].events  = POLLIN
  poll_fds[0].revents = 0
  rv = libc.poll poll_fds, 1, timeout_ms
  if rv > 0
    -- Lire et ignorer l'octet d'ACK (valeur 0x01).
    libc.read ack_rfd, ack_buf, 1
    return true
  -- Timeout ou erreur : fail-open (on rend quand même le verdict).
  log_warn { action: "nft_ack_timeout", worker_idx: worker_idx, seq: pending_seq, timeout_ms: timeout_ms }
  false

cmd_for = (kind, key, ip) ->
  if kind == "ip4"
    return "add element #{NFT_FAMILY} #{NFT_TABLE} #{NFT_SET_IP4} { #{key} . #{ip} timeout #{NFT_IP_TIMEOUT} }"
  if kind == "ip6"
    return "add element #{NFT_FAMILY6} #{NFT_TABLE} #{NFT_SET_IP6} { #{key} . #{ip} timeout #{NFT_IP_TIMEOUT} }"
  if kind == "mac4"
    return nil unless NFT_SET_MAC4
    return "add element #{NFT_FAMILY} #{NFT_TABLE} #{NFT_SET_MAC4} { #{key} . #{ip} timeout #{NFT_IP_TIMEOUT} }"
  if kind == "mac6"
    return nil unless NFT_SET_MAC6
    return "add element #{NFT_FAMILY6} #{NFT_TABLE} #{NFT_SET_MAC6} { #{key} . #{ip} timeout #{NFT_IP_TIMEOUT} }"
  nil

{ :set_wfd, :set_ack_rfd, :get_last_seq, :wait_ack, :add_ip4, :add_ip6, :add_mac4, :add_mac6, :cmd_for }
