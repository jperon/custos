{ :ffi, :libc } = require "ffi_defs"
{ :log_warn } = require "log"
config = require "config"

nft_cfg = config.nft or {}
FAMILY = nft_cfg.family or "bridge"
FAMILY6 = nft_cfg.family6 or "bridge"
TABLE = nft_cfg.table or "dns-filter-bridge"
SET_IP4 = nft_cfg.set_ip4 or "ip4_allowed"
SET_IP6 = nft_cfg.set_ip6 or "ip6_allowed"
SET_MAC4 = nft_cfg.set_mac4 or "mac4_allowed"
SET_MAC6 = nft_cfg.set_mac6 or "mac6_allowed"
IP_TIMEOUT = nft_cfg.ip_timeout or "2m"
ACK_TIMEOUT_MS = nft_cfg.ack_timeout_ms or 150

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
ack_buf   = ffi.new "uint8_t[1]"
drain_buf = ffi.new "uint8_t[64]"

is_valid_timeout = (t) ->
  return false unless type(t) == "string"
  return false unless #t > 0 and #t <= 16
  t\match("^%d+[smhdw]?$") ~= nil

to_hex = (s) ->
  return "" unless s and #s > 0
  (s\gsub ".", (c) -> string.format "%02x", c\byte!)

sanitize_timeout = (timeout) ->
  t = if timeout == nil then "" else tostring timeout
  if is_valid_timeout t
    return t
  fallback = IP_TIMEOUT
  if is_valid_timeout fallback
    log_warn { action: "nft_queue_timeout_invalid_fallback", timeout: t, fallback: fallback }
    return fallback
  log_warn { action: "nft_queue_timeout_invalid_default", timeout: t }
  "2m"

sleep_ms = (ms) ->
  sleep_req[0].tv_sec = math.floor ms / 1000
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  libc.nanosleep sleep_req, nil

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
      log_warn { action: "nft_queue_write_failed", fd: pipe_wfd, errno: errno }
      return false
    sleep_ms 10
  log_warn { action: "nft_queue_write_exhausted", fd: pipe_wfd }
  false

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

wait_ack = (pending_seq, corr) ->
  return false unless ack_rfd
  timeout_ms = ACK_TIMEOUT_MS
  poll_fds[0].fd      = ack_rfd
  poll_fds[0].events  = POLLIN
  poll_fds[0].revents = 0
  rv = libc.poll poll_fds, 1, timeout_ms
  if rv > 0
    libc.read ack_rfd, ack_buf, 1
    return true
  log_warn {
    action: "nft_ack_timeout"
    worker_idx: worker_idx
    seq: pending_seq
    corr: corr or ""
    timeout_ms: timeout_ms
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
    -- Fallback to global sets for unknown/empty rule_id
    if kind == "ip4"
      return SET_IP4
    if kind == "ip6"
      return SET_IP6
    if kind == "mac4"
      return SET_MAC4 if SET_MAC4
      return nil
    if kind == "mac6"
      return SET_MAC6 if SET_MAC6
      return nil
    if kind == "sip4"
      return "sip_peers"
    if kind == "sip6"
      return "sip_peers6"
    return nil
  
  if kind == "ip4" or kind == "ip6" or kind == "mac4" or kind == "mac6"
    return "rule_#{rule_id}_#{kind}"
  nil

-- cmd_for supports both 4-arg (backward compat) and 5-arg (new per-rule) calls
-- 4-arg: cmd_for(kind, key, ip, timeout)
-- 5-arg: cmd_for(kind, key, ip, rule_id, timeout)
cmd_lines_for = (kind, key, ip, rule_id_or_timeout, timeout) ->
  rule_id = nil
  -- Detect calling convention: if 5th arg is nil, 4th is timeout (old style)
  if timeout == nil
    -- Old 4-arg style: (kind, key, ip, timeout)
    timeout = rule_id_or_timeout
    rule_id = nil
  else
    -- New 5-arg style: (kind, key, ip, rule_id, timeout)
    rule_id = rule_id_or_timeout
  
  timeout = sanitize_timeout timeout
  set_name = get_set_name kind, rule_id
  return nil unless set_name
  set_names = { set_name }
  if rule_id and rule_id != ""
    if kind == "ip4" and SET_IP4
      set_names[#set_names + 1] = SET_IP4
    elseif kind == "ip6" and SET_IP6
      set_names[#set_names + 1] = SET_IP6
    elseif kind == "mac4" and SET_MAC4
      set_names[#set_names + 1] = SET_MAC4
    elseif kind == "mac6" and SET_MAC6
      set_names[#set_names + 1] = SET_MAC6

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
  return nil if #lines == 0
  lines

cmd_for = (kind, key, ip, rule_id_or_timeout, timeout) ->
  lines = cmd_lines_for kind, key, ip, rule_id_or_timeout, timeout
  return nil unless lines and #lines > 0
  table.concat lines, "\n"

{ :set_wfd, :set_ack_rfd, :get_last_seq, :wait_ack, :send_barrier, :add_ip4, :add_ip6, :add_mac4, :add_mac6, :add_sip4, :add_sip6, :cmd_for, :cmd_lines_for, :sanitize_timeout, :get_set_name, :sanitize_rule_id }
