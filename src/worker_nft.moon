{ :ffi, :libc } = require "ffi_defs"
{ :run_cmd } = require "nft"
{ :cmd_for, :sanitize_timeout } = require "nft_queue"
{ :log_info, :log_warn, :log_debug, :set_action_prefix } = require "log"

BUF_SIZE  = 8192
MAX_BATCH = 64
EAGAIN    = 11
EWOULDBLOCK = 11
POLLIN    = 1

LINE_VERSION = "v1"

read_buf  = ffi.new "char[?]", BUF_SIZE
ack_byte  = ffi.new "uint8_t[1]"
ack_byte[0] = 0x01
poll_fd   = ffi.new "struct pollfd[1]"

split_fields = (line) ->
  out = {}
  i = 1
  while true
    j = line\find "|", i, true
    if j
      out[#out + 1] = line\sub i, j - 1
      i = j + 1
    else
      out[#out + 1] = line\sub i
      break
  out

from_hex = (h) ->
  return "", nil if not h or #h == 0
  return nil, "hex_odd_length" if (#h % 2) != 0
  return nil, "hex_invalid_chars" unless h\match "^[0-9a-fA-F]+$"
  out = {}
  for i = 1, #h, 2
    out[#out + 1] = string.char tonumber(h\sub(i, i + 1), 16)
  table.concat(out), nil

is_ipv4 = (s) -> s and s\match "^%d+%.%d+%.%d+%.%d+$"
is_ipv6 = (s) -> s and s\find ":", 1, true
is_mac  = (s) -> s and s\match "^[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]$"

validate_item = (kind, key, ip) ->
  if kind == "ip4"
    return false unless is_ipv4(key) and is_ipv4(ip)
  elseif kind == "ip6"
    return false unless is_ipv6(key) and is_ipv6(ip)
  elseif kind == "mac4"
    return false unless is_mac(key) and is_ipv4(ip)
  elseif kind == "mac6"
    return false unless is_mac(key) and is_ipv6(ip)
  elseif kind == "sip4"
    return false unless is_ipv4(key)
  elseif kind == "sip6"
    return false unless is_ipv6(key)
  else
    return false
  true

parse_line = (line) ->
  parts = split_fields line
  return nil, "field_count" unless #parts == 9
  return nil, "version" unless parts[1] == LINE_VERSION
  kind, key, ip = parts[2], parts[3], parts[4]
  return nil, "tuple" unless validate_item kind, key, ip
  rule_id, err_rule = from_hex parts[5]
  return nil, "rule_id_#{err_rule}" if err_rule
  timeout = sanitize_timeout parts[6]
  seq = tonumber parts[7]
  return nil, "seq" unless seq and seq >= 0
  widx = tonumber parts[8]
  return nil, "worker_idx" unless widx
  corr, err_corr = from_hex parts[9]
  return nil, "corr_#{err_corr}" if err_corr
  {
    :kind
    :key
    :ip
    :rule_id
    :timeout
    :seq
    :widx
    :corr
  }, nil

send_ack = (ack_wfds, widx) ->
  return unless widx and widx >= 0
  wfd = ack_wfds[widx + 1]
  return unless wfd
  libc.write wfd, ack_byte, 1

-- Ajoute un item à `pending` avec déduplication par (kind,key,ip,timeout).
-- Retourne true si l'item a été ajouté (nouvelle clé), false si c'est un doublon.
-- Permet à l'appelant de tenir un compteur incrémental sans re-parcourir
-- `pending` (pairs) à chaque tour de boucle.
try_add_pending = (pending, item) ->
  entry_key = "#{item.kind}|#{item.key}|#{item.ip}|#{item.timeout}"
  return false if pending[entry_key]
  pending[entry_key] = item
  true

flush_batch = (pending, ack_queue, ack_wfds) ->
  lines = {}
  rule11_count = 0
  rule11_items = {}
  for _, item in pairs pending
    cmd = cmd_for item.kind, item.key, item.ip, item.rule_id, item.timeout
    lines[#lines + 1] = cmd if cmd
    if item.rule_id == "rule_11"
      rule11_count += 1
      rule11_items[#rule11_items + 1] = "#{item.kind}:#{item.key}>#{item.ip}"
  for k in pairs pending
    pending[k] = nil

  if #lines > 0
    cmd = table.concat lines, "\n"
    ok, err = run_cmd cmd, { quiet: true }
    if rule11_count > 0
      log_info -> { action: "nft_batch_rule", rule_id: "rule_11", count: rule11_count, ok: ok, items: table.concat(rule11_items, " ") }
    if ok
      log_debug -> { action: "batch_ok", count: #lines, acks: #ack_queue }
    else
      log_warn -> { action: "batch_failed", count: #lines, acks: #ack_queue, err: err or "" }
      for line in *lines
        ok_one, err_one = run_cmd line, { quiet: true }
        log_warn -> { action: "single_failed", err: err_one or "", cmd: line } unless ok_one
  else
    log_debug -> { action: "batch_ack_only", acks: #ack_queue }

  -- Send one ACK per unique worker (widx) that had items in this batch
  -- This fixes the race condition where worker_responses enqueues multiple items
  -- but only waits for one ACK. Previously we sent one ACK per item, causing
  -- ACKs to accumulate in the pipe and be consumed by wrong responses.
  workers_to_ack = {}
  for ack in *ack_queue
    workers_to_ack[ack.widx] = true
  for widx, _ in pairs workers_to_ack
    send_ack ack_wfds, widx
  for i = #ack_queue, 1, -1
    ack_queue[i] = nil

run = (rfd, ack_wfds) ->
  set_action_prefix "nft_"
  ack_wfds = ack_wfds or {}
  log_info -> { action: "worker_start", rfd: rfd, ack_workers: #ack_wfds }
  pending       = {}
  pending_count = 0
  ack_queue     = {}
  partial       = ""

  poll_fd[0].fd     = rfd
  poll_fd[0].events = POLLIN

  while true
    -- Bloque jusqu'à l'arrivée de données, SAUF s'il reste déjà une ligne
    -- complète bufferisée dans `partial` (cas d'un batch tronqué à MAX_BATCH au
    -- tour précédent) : on la traite immédiatement sans attendre le pipe. Un
    -- `partial` ne contenant qu'un fragment incomplet (sans `\n`) ne suffit pas :
    -- on bloque alors sur poll en attendant la fin de la ligne.
    unless partial\find "\n", 1, true
      poll_fd[0].revents = 0
      libc.poll poll_fd, 1, -1

    -- Draine : on consomme d'abord les lignes complètes déjà bufferisées, puis on
    -- lit le pipe (non bloquant) jusqu'à EAGAIN ou MAX_BATCH (borne la taille de
    -- la transaction nft).
    batch_full = false
    while not batch_full
      -- 1. Consommer les lignes complètes présentes dans `partial`.
      while true
        nl = partial\find "\n", 1, true
        break unless nl
        line = partial\sub 1, nl - 1
        partial = partial\sub nl + 1
        continue if #line == 0
        item, parse_err = parse_line line
        if item
          ack_queue[#ack_queue + 1] = { widx: item.widx, seq: item.seq, corr: item.corr, rule_id: item.rule_id }
          pending_count += 1 if try_add_pending pending, item
        else
          log_warn -> { action: "nft_invalid_message", reason: parse_err or "parse_failed", raw: line\sub(1, 220) }
        if pending_count >= MAX_BATCH
          batch_full = true
          break
      break if batch_full

      -- 2. Plus de ligne complète bufferisée : lire davantage (non bloquant).
      n = libc.read rfd, read_buf, BUF_SIZE
      if n and n > 0
        partial = partial .. ffi.string read_buf, n
        -- Garde-fou : un fragment géant sans `\n` ne doit pas croître sans fin.
        if #partial > 4096 and not partial\find "\n", 1, true
          log_warn -> { action: "nft_partial_oversize", size: #partial }
          partial = ""
      elseif n == 0
        -- EOF (tous les producteurs ont fermé) : on flush ce qui reste avant
        -- de sortir, pour un arrêt propre (best-effort).
        flush_batch pending, ack_queue, ack_wfds if pending_count > 0 or #ack_queue > 0
        log_warn -> { action: "pipe_closed", rfd: rfd }
        return
      else
        errno_p = libc.__errno_location!
        errno = if errno_p then errno_p[0] else 0
        break if errno == EAGAIN or errno == EWOULDBLOCK   -- pipe drainé → flush
        log_warn -> { action: "read_failed", rfd: rfd, errno: errno }
        break

    -- Flush dès que le pipe est drainé (ou le batch plein) : la latence est
    -- minimale (plus d'attente FLUSH_MS), et la coalescence reste naturelle
    -- sous charge — pendant la durée d'un flush, le pipe accumule les insertions
    -- suivantes, formant le batch d'après.
    if pending_count > 0 or #ack_queue > 0
      flush_batch pending, ack_queue, ack_wfds
      pending_count = 0

{ :run, :parse_line, :flush_batch, :try_add_pending, :split_fields, :from_hex }
