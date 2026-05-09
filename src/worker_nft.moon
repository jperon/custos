{ :ffi, :libc } = require "ffi_defs"
{ :run_cmd } = require "nft"
{ :cmd_for, :sanitize_timeout } = require "nft_queue"
{ :log_info, :log_warn, :log_debug, :set_action_prefix } = require "log"

BUF_SIZE  = 8192
MAX_BATCH = 64
FLUSH_MS  = 50
EAGAIN    = 11
EWOULDBLOCK = 11

LINE_VERSION = "v1"

sleep_req = ffi.new "timespec_t[1]"
clock_ts  = ffi.new "timespec_t[1]"
read_buf  = ffi.new "char[?]", BUF_SIZE
ack_byte  = ffi.new "uint8_t[1]"
ack_byte[0] = 0x01

sleep_ms = (ms) ->
  sleep_req[0].tv_sec = math.floor ms / 1000
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  libc.nanosleep sleep_req, nil

monotonic_ms = ->
  libc.clock_gettime 1, clock_ts
  tonumber(clock_ts[0].tv_sec) * 1000 + math.floor tonumber(clock_ts[0].tv_nsec) / 1000000

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

flush_batch = (pending, ack_queue, ack_wfds) ->
  count = 0
  for _, _ in pairs pending
    count += 1
  return if count == 0 and #ack_queue == 0

  lines = {}
  for _, item in pairs pending
    cmd = cmd_for item.kind, item.key, item.ip, item.timeout
    lines[#lines + 1] = cmd if cmd
  for k in pairs pending
    pending[k] = nil

  if #lines > 0
    cmd = table.concat lines, "\n"
    ok, err = run_cmd cmd, { quiet: true }
    if ok
      log_debug { action: "batch_ok", count: #lines, acks: #ack_queue }
    else
      log_warn { action: "batch_failed", count: #lines, acks: #ack_queue, err: err or "" }
      for line in *lines
        ok_one, err_one = run_cmd line, { quiet: true }
        log_warn { action: "single_failed", err: err_one or "", cmd: line } unless ok_one
  else
    log_debug { action: "batch_ack_only", acks: #ack_queue }

  for ack in *ack_queue
    send_ack ack_wfds, ack.widx
  for i = #ack_queue, 1, -1
    ack_queue[i] = nil

run = (rfd, ack_wfds) ->
  set_action_prefix "nft_"
  ack_wfds = ack_wfds or {}
  log_info { action: "worker_start", rfd: rfd, ack_workers: #ack_wfds }
  pending    = {}
  ack_queue  = {}
  partial    = ""
  last_flush = monotonic_ms!

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
        if #line == 0
          continue
        item, parse_err = parse_line line
        if item
          ack_queue[#ack_queue + 1] = { widx: item.widx, seq: item.seq, corr: item.corr, rule_id: item.rule_id }
          entry_key = "#{item.kind}|#{item.key}|#{item.ip}|#{item.timeout}"
          pending[entry_key] = item unless pending[entry_key]
        else
          log_warn { action: "nft_invalid_message", reason: parse_err or "parse_failed", raw: line\sub(1, 220) }
      partial = data
      if #partial > 4096
        log_warn { action: "nft_partial_oversize", size: #partial }
        partial = ""
    else
      errno_p = libc.__errno_location!
      errno = if errno_p then errno_p[0] else 0
      if n == 0
        log_warn { action: "pipe_closed", rfd: rfd }
        return
      if errno != EAGAIN and errno != EWOULDBLOCK
        log_warn { action: "read_failed", rfd: rfd, errno: errno }
        sleep_ms 100

    now_clock = monotonic_ms!
    pending_count = 0
    for _, _ in pairs pending
      pending_count += 1
    if pending_count >= MAX_BATCH or (#ack_queue >= MAX_BATCH) or ((pending_count > 0 or #ack_queue > 0) and now_clock - last_flush >= FLUSH_MS)
      flush_batch pending, ack_queue, ack_wfds
      last_flush = monotonic_ms!
    else
      sleep_ms 10

{ :run }
