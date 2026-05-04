{ :ffi, :libc } = require "ffi_defs"
{ :run_cmd } = require "nft"
{ :cmd_for } = require "nft_queue"
{ :log_info, :log_warn, :log_debug, :set_action_prefix } = require "log"

BUF_SIZE = 8192
MAX_BATCH = 64
FLUSH_MS = 50
EAGAIN = 11
EWOULDBLOCK = 11

sleep_req = ffi.new "timespec_t[1]"
read_buf = ffi.new "char[?]", BUF_SIZE

sleep_ms = (ms) ->
  sleep_req[0].tv_sec = math.floor ms / 1000
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  libc.nanosleep sleep_req, nil

parse_line = (line) ->
  kind, key, ip = line\match "^([^|]+)|([^|]+)|([^|]+)$"
  kind, key, ip

flush_batch = (pending) ->
  count = 0
  for _, _ in pairs pending
    count += 1
  return if count == 0

  lines = {}
  for _, item in pairs pending
    cmd = cmd_for item.kind, item.key, item.ip
    lines[#lines + 1] = cmd if cmd
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

run = (rfd) ->
  set_action_prefix "nft_"
  log_info { action: "worker_start", rfd: rfd }
  pending = {}
  partial = ""
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
        kind, key, ip = parse_line line
        if kind and key and ip
          pending["#{kind}|#{key}|#{ip}"] = { :kind, :key, :ip }
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
      flush_batch pending
      last_flush = os.clock!
    else
      sleep_ms 10

{ :run }
