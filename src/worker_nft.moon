{ :ffi, :libc } = require "ffi_defs"
{ :run_cmd } = require "nft"
{ :cmd_for } = require "nft_queue"
{ :log_info, :log_warn, :log_debug, :set_action_prefix } = require "log"

BUF_SIZE  = 8192
MAX_BATCH = 64
FLUSH_MS  = 50
EAGAIN    = 11
EWOULDBLOCK = 11

sleep_req = ffi.new "timespec_t[1]"
read_buf  = ffi.new "char[?]", BUF_SIZE
ack_byte  = ffi.new "uint8_t[1]"
ack_byte[0] = 0x01

sleep_ms = (ms) ->
  sleep_req[0].tv_sec = math.floor ms / 1000
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  libc.nanosleep sleep_req, nil

--- Parse une ligne du pipe nft.
-- Format court (compatibilité callers sans ACK) : "kind|key|ip"
-- Format étendu (avec ACK) :                     "kind|key|ip|seq|worker_idx"
-- @tparam  string line  ligne sans le \n final
-- @treturn string|nil kind, key, ip, seq (number|nil), worker_idx (number|nil)
parse_line = (line) ->
  -- Essaie d'abord le format étendu (5 champs).
  kind, key, ip, seq_s, widx_s = line\match "^([^|]+)|([^|]+)|([^|]+)|(%d+)|(%d+)$"
  if kind
    return kind, key, ip, tonumber(seq_s), tonumber(widx_s)
  -- Fallback format court (3 champs, sans ACK).
  kind, key, ip = line\match "^([^|]+)|([^|]+)|([^|]+)$"
  kind, key, ip, nil, nil

--- Envoie 1 octet d'ACK dans le pipe dédié au worker identifié par worker_idx.
-- @tparam table  ack_wfds  tableau des fd d'écriture ACK (1-indexed par worker_idx+1)
-- @tparam number widx      index du worker destinataire (0-based)
-- @treturn nil
send_ack = (ack_wfds, widx) ->
  wfd = ack_wfds[widx + 1]  -- tableau Lua 1-indexed
  return unless wfd
  libc.write wfd, ack_byte, 1

--- Exécute le batch d'insertions nft et ACK les workers concernés.
-- Vide la table pending en place.
-- @tparam table pending   { key = {kind, key, ip, worker_idx|nil, widx_set|nil} }
-- @tparam table ack_wfds  tableau des fd d'écriture ACK (peut être vide)
-- @treturn nil
flush_batch = (pending, ack_wfds) ->
  count = 0
  for _, _ in pairs pending
    count += 1
  return if count == 0

  lines  = {}
  -- Ensemble de tous les worker_idx à ACKer après ce flush.
  to_ack = {}
  for _, item in pairs pending
    cmd = cmd_for item.kind, item.key, item.ip
    lines[#lines + 1] = cmd if cmd
    -- Collecter le widx principal
    if item.worker_idx
      to_ack[item.worker_idx] = true
    -- Collecter les widx supplémentaires (même entrée, plusieurs workers en attente)
    if item.widx_set
      for widx, _ in pairs item.widx_set
        to_ack[widx] = true
  for k in pairs pending
    pending[k] = nil

  return if #lines == 0

  cmd = table.concat lines, "\n"
  ok, err = run_cmd cmd, { quiet: true }
  if ok
    log_debug { action: "batch_ok", count: #lines }
  else
    log_warn { action: "batch_failed", count: #lines, err: err or "" }
    for line in *lines
      ok_one, err_one = run_cmd line, { quiet: true }
      log_warn { action: "single_failed", err: err_one or "", cmd: line } unless ok_one

  -- ACK tous les workers ayant contribué au batch.
  -- On ACK même en cas d'échec partiel : la politique est fail-open côté Q1/DoH.
  for widx, _ in pairs to_ack
    send_ack ack_wfds, widx

--- Boucle principale du worker nft.
-- Lit des lignes depuis rfd, batchifie, flush périodiquement ou sur MAX_BATCH.
-- @tparam number rfd       fd de lecture du pipe nft
-- @tparam table  ack_wfds  tableau des fd d'écriture ACK (1-indexed, peut être nil)
-- @treturn nil
run = (rfd, ack_wfds) ->
  set_action_prefix "nft_"
  ack_wfds = ack_wfds or {}
  log_info { action: "worker_start", rfd: rfd, ack_workers: #ack_wfds }
  pending    = {}
  partial    = ""
  last_flush = os.clock!

  while true
    n = libc.read rfd, read_buf, BUF_SIZE
    if n and n > 0
      data = partial .. ffi.string read_buf, n
      partial = ""
      while true
        nl = data\find "\n", 1, true
        break unless nl
        line = data\sub 1, nl - 1
        data = data\sub nl + 1
        kind, key, ip, seq, widx = parse_line line
        if kind and key and ip
          entry_key = "#{kind}|#{key}|#{ip}"
          existing  = pending[entry_key]
          if existing
            -- Même paire (kind, key, ip) : dédoublonnée dans nft, mais plusieurs
            -- workers peuvent en attendre l'ACK → on accumule les widx.
            if widx
              if existing.worker_idx == widx
                nil  -- même worker, pas de doublon à gérer
              else
                existing.widx_set = existing.widx_set or {}
                existing.widx_set[existing.worker_idx] = true if existing.worker_idx
                existing.widx_set[widx] = true
                existing.worker_idx = nil  -- géré via widx_set désormais
          else
            pending[entry_key] = { :kind, :key, :ip, worker_idx: widx }
      partial = data
    else
      errno_p = libc.__errno_location!
      errno = if errno_p then errno_p[0] else 0
      if n == 0
        log_warn { action: "pipe_closed" }
        return
      if errno != EAGAIN and errno != EWOULDBLOCK
        log_warn { action: "read_failed", errno: errno }
        sleep_ms 100

    now_clock = os.clock!
    pending_count = 0
    for _, _ in pairs pending
      pending_count += 1
    if pending_count >= MAX_BATCH or (pending_count > 0 and (now_clock - last_flush) * 1000 >= FLUSH_MS)
      flush_batch pending, ack_wfds
      last_flush = os.clock!
    else
      sleep_ms 10

{ :run }
