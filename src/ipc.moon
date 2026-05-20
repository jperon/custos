-- src/ipc.moon
-- Protocole IPC entre worker_questions (question) et worker_responses (response).
-- Format A3 : message structuré, versionné, one-line.

{ :ffi, :libc } = require "ffi_defs"
config = require "config"
{ :log_warn } = require "log"

bit = require "bit"

runtime_cfg = config.runtime or {}
nft_cfg = config.nft or {}
ipc_cfg = config.ipc or {}

IPC_VERSION = "v1"
IPC_READ_CHUNK = 2048
IPC_MAX_LINE = 1024
IPC_WRITE_RETRY_COUNT = 5

EAGAIN = 11
EWOULDBLOCK = 11

timespec_ptr_t = ffi.typeof "timespec_t[1]"
read_buf = ffi.new "uint8_t[?]", IPC_READ_CHUNK

MSG_IPV4         = 0x41
MSG_IPV6         = 0x36
MSG_IPV4_REFUSED = 0x52
MSG_IPV6_REFUSED = 0x72
MSG_IPV4_DNSONLY = 0x44
MSG_IPV6_DNSONLY = 0x64
MSG_IPV4_ALLOW_IP4 = 0x45
MSG_IPV6_ALLOW_IP4 = 0x34
MSG_IPV4_ALLOW_IP6 = 0x61
MSG_IPV6_ALLOW_IP6 = 0x33
RESOLVER_IPV6_FLAG = 0x80

to_hex = (s) ->
  return "" unless s and #s > 0
  (s\gsub ".", (c) -> string.format "%02x", c\byte!)

from_hex = (h) ->
  return "", nil if not h or #h == 0
  return nil, "hex_odd_length" if (#h % 2) != 0
  return nil, "hex_invalid_chars" unless h\match "^[0-9a-fA-F]+$"
  out = {}
  for i = 1, #h, 2
    out[#out + 1] = string.char tonumber(h\sub(i, i + 1), 16)
  table.concat(out), nil

{ :mac2s } = require "ipparse.l2.ethernet"
{ :ip2s } = require "ipparse.l3.ip"

mac_raw_to_str = (mac_raw) ->
  return "00:00:00:00:00:00" unless mac_raw and #mac_raw == 6
  mac2s mac_raw

ip_raw_to_str = (ip_raw) ->
  return nil unless ip_raw and (#ip_raw == 4 or #ip_raw == 16)
  ip2s ip_raw

is_ipv4_str = (s) -> s and s\match "^%d+%.%d+%.%d+%.%d+$"
is_ipv6_str = (s) -> s and s\find ":", 1, true
is_valid_mac = (s) -> s and s\match "^[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]$"

is_valid_timeout = (t) ->
  return false unless type(t) == "string"
  return false unless #t > 0 and #t <= 16
  t\match("^%d+[smhdw]?$") ~= nil

msg_type_for = (ipv4, refused, dnsonly, allow_ip4, allow_ip6) ->
  if ipv4
    return MSG_IPV4_ALLOW_IP4 if allow_ip4
    return MSG_IPV4_ALLOW_IP6 if allow_ip6
    return MSG_IPV4_DNSONLY if dnsonly
    return MSG_IPV4_REFUSED if refused
    return MSG_IPV4
  return MSG_IPV6_ALLOW_IP4 if allow_ip4
  return MSG_IPV6_ALLOW_IP6 if allow_ip6
  return MSG_IPV6_DNSONLY if dnsonly
  return MSG_IPV6_REFUSED if refused
  MSG_IPV6

write_with_retry = (pipe_wfd, msg) ->
  sleep_req = timespec_ptr_t!
  for i = 1, IPC_WRITE_RETRY_COUNT
    n = libc.write pipe_wfd, msg, #msg
    return true if n == #msg
    errno_p = libc.__errno_location!
    errno = if errno_p then errno_p[0] else 0
    if errno != EAGAIN and errno != EWOULDBLOCK
      log_warn { action: "ipc_write_syscall_failed", fd: pipe_wfd, errno: errno, attempt: i }
      return false
    sleep_req[0].tv_sec = 0
    sleep_req[0].tv_nsec = 20000000
    libc.nanosleep sleep_req, nil
  errno_p = libc.__errno_location!
  errno = if errno_p then errno_p[0] else 0
  log_warn { action: "ipc_write_failed_exhausted", fd: pipe_wfd, errno: errno, attempts: IPC_WRITE_RETRY_COUNT }
  false

encode_msg = (txid, ip_raw, src_port, mac_raw, resolver_ip_raw, refused, dnsonly, allow_ip4, allow_ip6, reason, benchmark_ms, rule_id, timeout) ->
  return nil unless ip_raw and resolver_ip_raw
  return nil unless (#ip_raw == 4 or #ip_raw == 16)
  return nil unless (#resolver_ip_raw == 4 or #resolver_ip_raw == 16)

  ipv4 = #ip_raw == 4
  msg_type = msg_type_for ipv4, not not refused, not not dnsonly, not not allow_ip4, not not allow_ip6
  msg_type = bit.bor msg_type, RESOLVER_IPV6_FLAG if #resolver_ip_raw == 16

  client_ip = ip_raw_to_str ip_raw
  resolver_ip = ip_raw_to_str resolver_ip_raw
  return nil unless client_ip and resolver_ip

  timeout = timeout or nft_cfg.ip_timeout or "2m"
  timeout = tostring timeout
  return nil unless is_valid_timeout timeout

  reason = tostring(reason or "")
  rule_id = tostring(rule_id or "")
  if #reason > 63
    reason = reason\sub 1, 63
  if #rule_id > 63
    rule_id = rule_id\sub 1, 63

  bench = tonumber(benchmark_ms) or 0
  bench = 0 if bench < 0
  bench = math.floor bench

  line = table.concat({
    IPC_VERSION
    string.format "%02x", msg_type
    tostring(tonumber(txid) or 0)
    client_ip
    tostring(tonumber(src_port) or 0)
    resolver_ip
    mac_raw_to_str mac_raw
    to_hex reason or ""
    to_hex rule_id or ""
    timeout
    tostring bench
  }, "|") .. "\n"

  return nil if #line > IPC_MAX_LINE
  line

write_msg = (pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout) ->
  msg = encode_msg txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, false, false, false, reason, benchmark_ms, rule_id, timeout
  return false unless msg
  write_with_retry pipe_wfd, msg

write_refused_msg = (pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout) ->
  msg = encode_msg txid, ip_raw, src_port, mac_raw, resolver_ip_raw, true, false, false, false, reason, benchmark_ms, rule_id, timeout
  return false unless msg
  write_with_retry pipe_wfd, msg

write_dnsonly_msg = (pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout) ->
  msg = encode_msg txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, true, false, false, reason, benchmark_ms, rule_id, timeout
  return false unless msg
  write_with_retry pipe_wfd, msg

write_allow_ip4_msg = (pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout) ->
  msg = encode_msg txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, false, true, false, reason, benchmark_ms, rule_id, timeout
  return false unless msg
  write_with_retry pipe_wfd, msg

write_allow_ip6_msg = (pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout) ->
  msg = encode_msg txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, false, false, true, reason, benchmark_ms, rule_id, timeout
  return false unless msg
  write_with_retry pipe_wfd, msg

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

decode_msg = (raw) ->
  return nil, "empty" unless raw and #raw > 0
  line = raw\gsub "\n+$", ""
  parts = split_fields line
  return nil, "field_count" unless #parts == 11

  version = parts[1]
  return nil, "version" unless version == IPC_VERSION

  msg_type_full = tonumber parts[2], 16
  return nil, "msg_type" unless msg_type_full
  msg_type = bit.band msg_type_full, 0x7F
  resolver_ipv6 = bit.band(msg_type_full, RESOLVER_IPV6_FLAG) != 0

  txid = tonumber parts[3]
  src_port = tonumber parts[5]
  benchmark_num = tonumber parts[11]
  return nil, "txid" unless txid and txid >= 0 and txid <= 65535
  return nil, "src_port" unless src_port and src_port >= 0 and src_port <= 65535
  benchmark_num = 0 unless benchmark_num and benchmark_num >= 0

  ipv4 = (msg_type == MSG_IPV4 or msg_type == MSG_IPV4_REFUSED or msg_type == MSG_IPV4_DNSONLY or msg_type == MSG_IPV4_ALLOW_IP4 or msg_type == MSG_IPV4_ALLOW_IP6)
  return nil, "family" unless ipv4 or msg_type == MSG_IPV6 or msg_type == MSG_IPV6_REFUSED or msg_type == MSG_IPV6_DNSONLY or msg_type == MSG_IPV6_ALLOW_IP4 or msg_type == MSG_IPV6_ALLOW_IP6
  refused = (msg_type == MSG_IPV4_REFUSED or msg_type == MSG_IPV6_REFUSED)
  dnsonly = (msg_type == MSG_IPV4_DNSONLY or msg_type == MSG_IPV6_DNSONLY)
  allow_ip4 = (msg_type == MSG_IPV4_ALLOW_IP4 or msg_type == MSG_IPV6_ALLOW_IP4)
  allow_ip6 = (msg_type == MSG_IPV4_ALLOW_IP6 or msg_type == MSG_IPV6_ALLOW_IP6)

  ip_str = parts[4]
  resolver_ip_str = parts[6]
  return nil, "ip_client" unless (ipv4 and is_ipv4_str(ip_str)) or ((not ipv4) and is_ipv6_str(ip_str))
  return nil, "ip_resolver" unless (resolver_ipv6 and is_ipv6_str(resolver_ip_str)) or ((not resolver_ipv6) and is_ipv4_str(resolver_ip_str))

  mac_str = parts[7]\lower!
  return nil, "mac" unless is_valid_mac mac_str

  reason, reason_err = from_hex parts[8]
  return nil, "reason_#{reason_err}" if reason_err
  rule_id, rule_err = from_hex parts[9]
  return nil, "rule_id_#{rule_err}" if rule_err

  timeout = parts[10]
  return nil, "timeout" unless is_valid_timeout timeout

  benchmark_ms = if benchmark_num > 0 then benchmark_num else nil

  {
    :txid
    :ip_str
    :src_port
    :resolver_ip_str
    :msg_type
    :mac_str
    :ipv4
    :refused
    :dnsonly
    :allow_ip4
    :allow_ip6
    :reason
    :benchmark_ms
    :rule_id
    :timeout
  }, nil

pending = {}
read_states = {}

make_key = (txid, ip_str, src_port, resolver_ip_str) ->
  string.format "%04x:%s:%d:%s", txid, ip_str, src_port, resolver_ip_str

set_pending = (msg, now_fn) ->
  key = make_key msg.txid, msg.ip_str, msg.src_port, msg.resolver_ip_str
  pending[key] = {
    expire: now_fn! + (ipc_cfg.pending_ttl or 5)
    refused: msg.refused
    dnsonly: msg.dnsonly
    allow_ip4: msg.allow_ip4
    allow_ip6: msg.allow_ip6
    reason: msg.reason
    benchmark_ms: msg.benchmark_ms
    rule_id: msg.rule_id
    timeout: msg.timeout
  }

drain_lines = (pipe_rfd, buf, now_fn, on_msg) ->
  absorbed = 0
  while true
    nl = buf\find "\n", 1, true
    break unless nl
    line = buf\sub 1, nl - 1
    buf = buf\sub nl + 1
    if #line == 0
      continue
    msg, err = decode_msg line
    if msg
      set_pending msg, now_fn
      absorbed += 1
      on_msg msg if on_msg
    else
      log_warn { action: "ipc_invalid_message", fd: pipe_rfd, reason: err or "decode_failed", raw: line\sub(1, 180) }
  buf, absorbed

drain_pipe = (pipe_rfd, now_fn, on_msg) ->
  state = read_states[pipe_rfd] or ""
  absorbed = 0
  while true
    n = libc.read pipe_rfd, read_buf, IPC_READ_CHUNK
    if n == 0
      log_warn { action: "ipc_pipe_eof", fd: pipe_rfd }
      break
    if n < 0
      errno_p = libc.__errno_location!
      errno = if errno_p then errno_p[0] else 0
      break if errno == EAGAIN or errno == EWOULDBLOCK
      log_warn { action: "ipc_read_failed", fd: pipe_rfd, errno: errno }
      break
    state ..= ffi.string read_buf, n
    if #state > IPC_MAX_LINE * 4
      log_warn { action: "ipc_buffer_oversize", fd: pipe_rfd, size: #state }
      state = ""
    state, added = drain_lines pipe_rfd, state, now_fn, on_msg
    absorbed += added
    break if n < IPC_READ_CHUNK
  read_states[pipe_rfd] = state
  absorbed

is_pending = (txid, ip_str, src_port, resolver_ip_str, now_fn) ->
  key = make_key txid, ip_str, src_port, resolver_ip_str
  entry = pending[key]
  return false unless entry
  if now_fn! > entry.expire
    pending[key] = nil
    return false
  true

get_pending_entry = (txid, ip_str, src_port, resolver_ip_str, now_fn) ->
  key = make_key txid, ip_str, src_port, resolver_ip_str
  entry = pending[key]
  return nil unless entry
  if now_fn! > entry.expire
    pending[key] = nil
    return nil
  entry

consume = (txid, ip_str, src_port, resolver_ip_str) ->
  key = make_key txid, ip_str, src_port, resolver_ip_str
  pending[key] = nil

{
  :encode_msg
  :decode_msg
  :write_msg
  :write_refused_msg
  :write_dnsonly_msg
  :write_allow_ip4_msg
  :write_allow_ip6_msg
  :drain_pipe
  :is_pending
  :get_pending_entry
  :consume
  :MSG_IPV4
  :MSG_IPV6
  :MSG_IPV4_REFUSED
  :MSG_IPV6_REFUSED
  :MSG_IPV4_DNSONLY
  :MSG_IPV6_DNSONLY
  :MSG_IPV4_ALLOW_IP4
  :MSG_IPV6_ALLOW_IP4
  :MSG_IPV4_ALLOW_IP6
  :MSG_IPV6_ALLOW_IP6
  :make_key
}
