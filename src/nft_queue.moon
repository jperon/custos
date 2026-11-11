{ :ffi, :libc } = require "ffi_defs"
{ :log_warn } = require "log"
config = require "config"
{ :to_hex, :is_valid_timeout } = require "lib.ipc_hex"

nft_cfg = config.nft or {}
FAMILY = nft_cfg.family or "bridge"
FAMILY6 = nft_cfg.family6 or "bridge"
TABLE = nft_cfg.table or "dns-filter-bridge"
IP_TIMEOUT = nft_cfg.ip_timeout or "2m"
ACK_TIMEOUT_MS  = nft_cfg.ack_timeout_ms or 150
WAIT_POLL_MS    = 5   -- intervalle de poll dans wait_ack pour permettre le drain intercalé

-- Format d'ACK : un enregistrement de taille FIXE, écrit en un seul write
-- (≤ PIPE_BUF, donc atomique) et portant le plus grand `seq` appliqué par
-- worker_nft pour ce worker. Un uint64 natif suffit : les deux extrémités
-- vivent sur la même machine (même ordre d'octets).
ACK_SIZE = 8
CLOCK_MONOTONIC = 1

PIPE_BUF_SAFE = 512
IPC_WRITE_RETRY_COUNT = 3
EAGAIN = 11
EWOULDBLOCK = 11
POLLIN = 1

LINE_VERSION = "v1"

pipe_wfd = nil
ack_rfd = nil
worker_idx = nil
seq = 0
last_enqueued_seq = nil

sleep_req = ffi.new "timespec_t[1]"
poll_fds  = ffi.new "struct pollfd[1]"
-- Accumulateur de lecture d'un ACK : un enregistrement peut arriver en
-- plusieurs morceaux (lecture partielle), il n'est interprété que complet.
ack_rec   = ffi.new "uint8_t[?]", ACK_SIZE
ack_val   = ffi.new "uint64_t[1]"
drain_buf = ffi.new "uint8_t[64]"

sanitize_timeout = (timeout) ->
  t = if timeout == nil then "" else tostring timeout
  if is_valid_timeout t
    return t
  fallback = IP_TIMEOUT
  if is_valid_timeout fallback
    log_warn -> { action: "nft_queue_timeout_invalid_fallback", timeout: t, fallback: fallback }
    return fallback
  log_warn -> { action: "nft_queue_timeout_invalid_default", timeout: t }
  "2m"

sleep_ms = (ms) ->
  sleep_req[0].tv_sec = math.floor ms / 1000
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  libc.nanosleep sleep_req, nil

-- Millisecondes monotones depuis le démarrage (budget global de wait_ack).
monotonic_ms = ->
  libc.clock_gettime CLOCK_MONOTONIC, sleep_req
  tonumber(sleep_req[0].tv_sec) * 1000 + math.floor(tonumber(sleep_req[0].tv_nsec) / 1000000)

-- Décode l'enregistrement ACK complet accumulé dans `ack_rec`.
ack_rec_seq = ->
  ffi.copy ack_val, ack_rec, ACK_SIZE
  tonumber ack_val[0]

set_wfd = (wfd) ->
  pipe_wfd = wfd

set_ack_rfd = (rfd, idx) ->
  ack_rfd    = rfd
  worker_idx = idx

write_line = (line) ->
  return false unless pipe_wfd
  return false if #line > PIPE_BUF_SAFE
  for _ = 1, IPC_WRITE_RETRY_COUNT
    n = libc.write pipe_wfd, line, #line
    return true if n == #line
    errno_p = libc.__errno_location!
    errno = if errno_p then errno_p[0] else 0
    if errno != EAGAIN and errno != EWOULDBLOCK
      log_warn -> { action: "nft_queue_write_failed", fd: pipe_wfd, errno: errno }
      return false
    sleep_ms 10
  log_warn -> { action: "nft_queue_write_exhausted", fd: pipe_wfd }
  false

-- Vide entièrement le tube ACK : enregistrements complets comme fragments
-- partiels éventuels (le format est de taille fixe, tout octet restant serait
-- interprété comme le début d'un ACK par wait_ack).
drain_ack = ->
  return unless ack_rfd
  while true
    n = libc.read ack_rfd, drain_buf, 64
    break unless n and n > 0

build_line = (kind, key, ip, rule_id, timeout, corr, item_seq, widx) ->
  table.concat({
    LINE_VERSION
    kind
    key
    ip
    to_hex rule_id or ""
    timeout
    tostring item_seq
    tostring widx or -1
    to_hex corr or ""
  }, "|") .. "\n"

enqueue = (kind, key, ip, rule_id, timeout, corr) ->
  return false unless kind and key and ip
  timeout = sanitize_timeout timeout
  seq += 1
  line = build_line kind, key, ip, rule_id, timeout, corr, seq, worker_idx
  ok = write_line line
  last_enqueued_seq = seq if ok
  ok

add_ip4  = (client_ip, ip_str, rule_id, timeout, corr) -> enqueue "ip4",  client_ip, ip_str, rule_id, timeout, corr
add_ip6  = (client_ip, ip_str, rule_id, timeout, corr) -> enqueue "ip6",  client_ip, ip_str, rule_id, timeout, corr
add_mac4 = (mac, ip_str, rule_id, timeout, corr)       -> enqueue "mac4", mac,       ip_str, rule_id, timeout, corr
add_mac6 = (mac, ip_str, rule_id, timeout, corr)       -> enqueue "mac6", mac,       ip_str, rule_id, timeout, corr
add_sip4 = (ip_str, rule_id, timeout, corr)            -> enqueue "sip4", ip_str,    ip_str, rule_id, timeout, corr
add_sip6 = (ip_str, rule_id, timeout, corr)            -> enqueue "sip6", ip_str,    ip_str, rule_id, timeout, corr
add_auth_mac = (mac, rule_id, timeout, corr)           -> enqueue "auth_mac", mac, "_", rule_id, timeout, corr
add_auth_ip4 = (ip, rule_id, timeout, corr)            -> enqueue "auth_ip4", ip, "_", rule_id, timeout, corr
add_auth_ip6 = (ip, rule_id, timeout, corr)            -> enqueue "auth_ip6", ip, "_", rule_id, timeout, corr

send_barrier = (corr) ->
  return false unless pipe_wfd
  drain_ack!
  seq += 1
  line = build_line "barrier", "_", "_", "", "0s", corr, seq, worker_idx
  ok = write_line line
  last_enqueued_seq = seq if ok
  ok

get_last_seq = ->
  s = last_enqueued_seq
  last_enqueued_seq = nil
  s

-- Index du worker propriétaire du tube ACK (0-based), exposé pour dériver le
-- chemin d'un verrou inter-processus propre à ce worker (cf. doh.query).
get_worker_idx = ->
  worker_idx

-- Attend l'ACK de worker_nft pour le batch courant.
-- Un ACK est un enregistrement de taille fixe (ACK_SIZE) portant le plus grand
-- `seq` appliqué par worker_nft pour ce worker. `wait_ack` ne rend la main que
-- lorsque ce seq atteint `pending_seq` : les ACK d'un batch antérieur (seq
-- strictement inférieur, p. ex. les 64 premiers éléments d'un inject coupé par
-- MAX_BATCH) sont ignorés et l'attente continue, sans dépasser le budget global
-- ACK_TIMEOUT_MS.
-- `seq` est un compteur Lua monotone par processus (jamais remis à zéro dans un
-- processus vivant) : aucun rebouclage n'est possible avant 2^53 insertions
-- (des siècles au débit réel). Un redémarrage du producteur repart de zéro ; les
-- ACK résiduels du tube sont purgés par drain_ack! avant l'injection suivante.
-- on_wait (optionnel) est appelé à chaque tour d'attente, typiquement pour
-- drainer le pipe IPC question→response pendant l'attente, sans bloquer le
-- pipe et sans toucher à l'ordre nft-avant-verdict.
wait_ack = (pending_seq, corr, on_wait) ->
  return false unless ack_rfd
  target = pending_seq or 0
  deadline = monotonic_ms! + ACK_TIMEOUT_MS
  poll_fds[0].fd     = ack_rfd
  poll_fds[0].events = POLLIN
  have = 0
  while true
    remaining = deadline - monotonic_ms!
    break if remaining <= 0
    poll_fds[0].revents = 0
    rv = libc.poll poll_fds, 1, math.min(WAIT_POLL_MS, remaining)
    if rv > 0
      n = libc.read ack_rfd, ack_rec + have, ACK_SIZE - have
      if n and n > 0
        have += n
        if have >= ACK_SIZE
          acked = ack_rec_seq!
          have = 0
          return true if acked >= target
          -- ACK périmé : l'attente continue dans le MÊME budget.
      elseif n == 0
        -- Tube fermé (worker_nft absent) : rien ne viendra plus. On laisse
        -- expirer le budget au lieu de tourner à vide sur POLLHUP.
        sleep_ms WAIT_POLL_MS
    on_wait! if on_wait
  log_warn -> {
    action: "nft_ack_timeout"
    worker_idx: worker_idx
    seq: pending_seq
    corr: corr or ""
    timeout_ms: ACK_TIMEOUT_MS
  }
  false

sanitize_rule_id = (rule_id) ->
  return "" unless rule_id
  s = tostring rule_id
  return "" if #s == 0
  -- Rule IDs should be hex-decodable; limit to 63 bytes for safety
  if #s > 126
    s = s\sub 1, 126
  s

get_set_name = (kind, rule_id) ->
  rule_id = sanitize_rule_id rule_id
  if rule_id == ""
    -- No fallback to global sets: rule_id is required for per-rule sets
    if kind == "sip4"
      return "sip_peers"
    if kind == "sip6"
      return "sip_peers6"
    return nil

  if kind == "auth_mac"
    return "#{rule_id}_auth_mac"
  if kind == "auth_ip4"
    return "#{rule_id}_auth_ip4"
  if kind == "auth_ip6"
    return "#{rule_id}_auth_ip6"
  if kind == "ip4" or kind == "ip6" or kind == "mac4" or kind == "mac6"
    return "#{rule_id}_#{kind}"
  nil

-- cmd_for(kind, key, ip, rule_id, timeout)
cmd_lines_for = (kind, key, ip, rule_id, timeout) ->
  timeout = sanitize_timeout timeout
  set_name = get_set_name kind, rule_id
  return nil unless set_name
  set_names = { set_name }

  lines = {}
  for _, name in ipairs set_names
    if kind == "ip4"
      lines[#lines + 1] = "add element #{FAMILY} #{TABLE} #{name} { #{key} . #{ip} timeout #{timeout} }"
    elseif kind == "ip6"
      lines[#lines + 1] = "add element #{FAMILY6} #{TABLE} #{name} { #{key} . #{ip} timeout #{timeout} }"
    elseif kind == "mac4"
      lines[#lines + 1] = "add element #{FAMILY} #{TABLE} #{name} { #{key} . #{ip} timeout #{timeout} }"
    elseif kind == "mac6"
      lines[#lines + 1] = "add element #{FAMILY6} #{TABLE} #{name} { #{key} . #{ip} timeout #{timeout} }"
    elseif kind == "sip4"
      lines[#lines + 1] = "add element #{FAMILY} #{TABLE} #{name} { #{key} timeout #{timeout} }"
    elseif kind == "sip6"
      lines[#lines + 1] = "add element #{FAMILY6} #{TABLE} #{name} { #{key} timeout #{timeout} }"
    elseif kind == "auth_mac"
      lines[#lines + 1] = "add element #{FAMILY} #{TABLE} #{name} { #{key} timeout #{timeout} }"
    elseif kind == "auth_ip4"
      lines[#lines + 1] = "add element #{FAMILY} #{TABLE} #{name} { #{key} timeout #{timeout} }"
    elseif kind == "auth_ip6"
      lines[#lines + 1] = "add element #{FAMILY6} #{TABLE} #{name} { #{key} timeout #{timeout} }"
  return nil if #lines == 0
  lines

cmd_for = (kind, key, ip, rule_id, timeout) ->
  lines = cmd_lines_for kind, key, ip, rule_id, timeout
  return nil unless lines and #lines > 0
  table.concat lines, "\n"

{ :set_wfd, :set_ack_rfd, :get_last_seq, :get_worker_idx, :wait_ack, :drain_ack, :send_barrier, :add_ip4, :add_ip6, :add_mac4, :add_mac6, :add_sip4, :add_sip6, :add_auth_mac, :add_auth_ip4, :add_auth_ip6, :cmd_for, :cmd_lines_for, :sanitize_timeout, :get_set_name, :sanitize_rule_id, :ACK_SIZE }
