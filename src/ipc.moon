-- src/ipc.moon
-- Protocole IPC entre worker_questions et worker_responses.
-- Format A4 : 12 champs pipe-séparés, one-line, versionné.
--
-- Les modificateurs comportementaux (dnsonly, strip_aaaa, …) sont encodés
-- dans un champ bitmask générique « mods » : les modules action s'enregistrent
-- via register_modifier ; les bits sont attribués à la première utilisation
-- (tri alphabétique → déterminisme entre les deux workers).
-- Ajouter un nouveau type d'action = appeler register_modifier une fois.
-- Aucune constante MSG_XXX par type d'action.

{ :ffi, :libc } = require "ffi_defs"
config = require "config"
{ :log_warn } = require "log"

bit = require "bit"

runtime_cfg = config.runtime or {}
nft_cfg     = config.nft    or {}
ipc_cfg     = config.ipc    or {}

IPC_VERSION        = "v1"
IPC_READ_CHUNK     = 2048
IPC_MAX_LINE       = 1024
IPC_WRITE_RETRY_COUNT = 5

EAGAIN       = 11
EWOULDBLOCK  = 11

timespec_ptr_t = ffi.typeof "timespec_t[1]"
read_buf       = ffi.new "uint8_t[?]", IPC_READ_CHUNK

-- ── Types de messages : famille + refus uniquement ──────────────────
MSG_IPV4         = 0x41   -- 'A'
MSG_IPV6         = 0x36   -- '6'
MSG_IPV4_REFUSED = 0x52   -- 'R'
MSG_IPV6_REFUSED = 0x72   -- 'r'
RESOLVER_IPV6_FLAG = 0x80

-- ── Registre dynamique des modificateurs ────────────────────────────
-- Les modules action appellent register_modifier au chargement.
-- _finalize! trie les noms et attribue les bits (idem dans les deux workers
-- car ils chargent les mêmes modules depuis la même config filtre).
_registered = {}
_mod_bits   = {}
_finalized  = false

_finalize = ->
  return if _finalized
  table.sort _registered
  for i, name in ipairs _registered
    _mod_bits[name] = bit.lshift 1, (i - 1)
  _finalized = true

--- Enregistre un modificateur IPC.  Appelé par les modules action au chargement.
-- @tparam string name  Nom du modificateur (ex: "dnsonly", "strip_aaaa")
register_modifier = (name) ->
  for existing in *_registered
    return if existing == name
  _registered[#_registered + 1] = name
  _finalized = false  -- forcer re-finalize si de nouveaux modules chargés

--- Retourne le bit assigné à un modificateur (finalise si nécessaire).
modifier_bit = (name) ->
  _finalize! unless _finalized
  _mod_bits[name] or 0

--- Encode une table {name → bool} en entier bitmask.
encode_modifiers = (mods) ->
  return 0 unless mods
  _finalize! unless _finalized
  result = 0
  for name, val in pairs mods
    b = _mod_bits[name]
    result = bit.bor result, b if b and val
  result

--- Decode un entier bitmask en table {name → bool}.
decode_modifiers = (bits) ->
  _finalize! unless _finalized
  result = {}
  for name, b in pairs _mod_bits
    result[name] = bit.band(bits, b) != 0
  result

-- ── Helpers ──────────────────────────────────────────────────────────
to_hex = (s) ->
  return "" unless s and #s > 0
  (s\gsub ".", (c) -> string.format "%02x", c\byte!)

from_hex = (h) ->
  return "", nil if not h or #h == 0
  return nil, "hex_odd_length"   if (#h % 2) != 0
  return nil, "hex_invalid_chars" unless h\match "^[0-9a-fA-F]+$"
  out = {}
  for i = 1, #h, 2
    out[#out + 1] = string.char tonumber(h\sub(i, i + 1), 16)
  table.concat(out), nil

{ :mac2s } = require "ipparse.l2.ethernet"
{ :ip2s }  = require "ipparse.l3.ip"

mac_raw_to_str = (mac_raw) ->
  return "00:00:00:00:00:00" unless mac_raw and #mac_raw == 6
  mac2s mac_raw

ip_raw_to_str = (ip_raw) ->
  return nil unless ip_raw and (#ip_raw == 4 or #ip_raw == 16)
  ip2s ip_raw

is_ipv4_str    = (s) -> s and s\match "^%d+%.%d+%.%d+%.%d+$"
is_ipv6_str    = (s) -> s and s\find ":", 1, true
is_valid_mac   = (s) -> s and s\match "^[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]$"
is_valid_timeout = (t) ->
  return false unless type(t) == "string"
  return false unless #t > 0 and #t <= 16
  t\match("^%d+[smhdw]?$") ~= nil

msg_type_for = (ipv4, refused) ->
  if ipv4
    return MSG_IPV4_REFUSED if refused
    return MSG_IPV4
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
      log_warn -> { action: "ipc_write_syscall_failed", fd: pipe_wfd, errno: errno, attempt: i }
      return false
    sleep_req[0].tv_sec = 0
    sleep_req[0].tv_nsec = 20000000
    libc.nanosleep sleep_req, nil
  errno_p = libc.__errno_location!
  errno = if errno_p then errno_p[0] else 0
  log_warn -> { action: "ipc_write_failed_exhausted", fd: pipe_wfd, errno: errno, attempts: IPC_WRITE_RETRY_COUNT }
  false

--- Encode un message IPC.
-- @tparam number      txid          Transaction DNS
-- @tparam string      ip_raw        IP source (4 ou 16 octets)
-- @tparam number      src_port      Port source
-- @tparam string      mac_raw       MAC source (6 octets)
-- @tparam string      resolver_ip_raw IP résolveur
-- @tparam boolean     refused       true si réponse REFUSED
-- @tparam string      reason        Raison (tronquée à 63 chars)
-- @tparam number|nil  benchmark_ms  Latence mesurée
-- @tparam string|nil  rule_id       Identifiant de règle
-- @tparam string|nil  timeout       Timeout nft (ex: "2m")
-- @tparam table|nil   modifiers     Table {nom → bool} des modificateurs actifs
-- @treturn string|nil Ligne IPC prête à écrire, ou nil si invalide
encode_msg = (txid, ip_raw, src_port, mac_raw, resolver_ip_raw, refused, reason, benchmark_ms, rule_id, timeout, modifiers) ->
  return nil unless ip_raw and resolver_ip_raw
  return nil unless (#ip_raw == 4 or #ip_raw == 16)
  return nil unless (#resolver_ip_raw == 4 or #resolver_ip_raw == 16)

  ipv4     = #ip_raw == 4
  msg_type = msg_type_for ipv4, not not refused
  msg_type = bit.bor msg_type, RESOLVER_IPV6_FLAG if #resolver_ip_raw == 16

  client_ip   = ip_raw_to_str ip_raw
  resolver_ip = ip_raw_to_str resolver_ip_raw
  return nil unless client_ip and resolver_ip

  timeout = timeout or nft_cfg.ip_timeout or "2m"
  timeout = tostring timeout
  return nil unless is_valid_timeout timeout

  reason  = tostring(reason  or "")
  rule_id = tostring(rule_id or "")
  reason  = reason\sub(1, 63)   if #reason  > 63
  -- rule_id : aligner sur la limite filter.rule_id.sanitize_id (128 chars)
  -- + le préfixe "r_" = 130 chars max. La limite précédente (63) tronquait
  -- les rule_ids longs et désynchronisait les noms de sets nft côté worker.
  rule_id = rule_id\sub(1, 130) if #rule_id > 130

  bench = tonumber(benchmark_ms) or 0
  bench = 0 if bench < 0
  bench = math.floor bench

  mods_bits = encode_modifiers modifiers
  line = table.concat({
    IPC_VERSION
    string.format "%02x", msg_type
    tostring(tonumber(txid) or 0)
    client_ip
    tostring(tonumber(src_port) or 0)
    resolver_ip
    mac_raw_to_str mac_raw
    to_hex reason
    to_hex rule_id
    timeout
    tostring bench
    string.format "%x", mods_bits
  }, "|") .. "\n"

  return nil if #line > IPC_MAX_LINE
  line

write_msg = (pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout, modifiers) ->
  msg = encode_msg txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, reason, benchmark_ms, rule_id, timeout, modifiers
  return false unless msg
  write_with_retry pipe_wfd, msg

write_refused_msg = (pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout, modifiers) ->
  msg = encode_msg txid, ip_raw, src_port, mac_raw, resolver_ip_raw, true, reason, benchmark_ms, rule_id, timeout, modifiers
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
  line  = raw\gsub "\n+$", ""
  parts = split_fields line
  return nil, "field_count" unless #parts >= 11

  version = parts[1]
  return nil, "version" unless version == IPC_VERSION

  msg_type_full = tonumber parts[2], 16
  return nil, "msg_type" unless msg_type_full
  msg_type      = bit.band msg_type_full, 0x7F
  resolver_ipv6 = bit.band(msg_type_full, RESOLVER_IPV6_FLAG) != 0

  txid          = tonumber parts[3]
  src_port      = tonumber parts[5]
  benchmark_num = tonumber parts[11]
  return nil, "txid"     unless txid     and txid     >= 0 and txid     <= 65535
  return nil, "src_port" unless src_port and src_port >= 0 and src_port <= 65535
  benchmark_num = 0 unless benchmark_num and benchmark_num >= 0

  ipv4    = (msg_type == MSG_IPV4 or msg_type == MSG_IPV4_REFUSED)
  return nil, "family" unless ipv4 or msg_type == MSG_IPV6 or msg_type == MSG_IPV6_REFUSED
  refused = (msg_type == MSG_IPV4_REFUSED or msg_type == MSG_IPV6_REFUSED)

  ip_str          = parts[4]
  resolver_ip_str = parts[6]
  return nil, "ip_client"   unless (ipv4 and is_ipv4_str(ip_str))   or ((not ipv4) and is_ipv6_str(ip_str))
  return nil, "ip_resolver" unless (resolver_ipv6 and is_ipv6_str(resolver_ip_str)) or
                                    ((not resolver_ipv6) and is_ipv4_str(resolver_ip_str))

  mac_str = parts[7]\lower!
  return nil, "mac" unless is_valid_mac mac_str

  reason,  reason_err  = from_hex parts[8]
  return nil, "reason_#{reason_err}"  if reason_err
  rule_id, rule_err    = from_hex parts[9]
  return nil, "rule_id_#{rule_err}"   if rule_err

  timeout = parts[10]
  return nil, "timeout" unless is_valid_timeout timeout

  benchmark_ms = if benchmark_num > 0 then benchmark_num else nil

  -- Champ mods optionnel (rétrocompatibilité messages 11 champs)
  mods_hex  = parts[12] or "0"
  mods_bits = tonumber(mods_hex, 16) or 0
  modifiers = decode_modifiers mods_bits

  {
    :txid
    :ip_str
    :src_port
    :resolver_ip_str
    :msg_type
    :mac_str
    :ipv4
    :refused
    :reason
    :benchmark_ms
    :rule_id
    :timeout
    :modifiers
  }, nil

pending     = {}
read_states = {}

make_key = (txid, ip_str, src_port, resolver_ip_str) ->
  string.format "%04x:%s:%d:%s", txid, ip_str, src_port, resolver_ip_str

set_pending = (msg, now_fn) ->
  key = make_key msg.txid, msg.ip_str, msg.src_port, msg.resolver_ip_str
  pending[key] = {
    expire:       now_fn! + (ipc_cfg.pending_ttl or 5)
    refused:      msg.refused
    modifiers:    msg.modifiers
    reason:       msg.reason
    benchmark_ms: msg.benchmark_ms
    rule_id:      msg.rule_id
    timeout:      msg.timeout
  }

drain_lines = (pipe_rfd, buf, now_fn, on_msg) ->
  absorbed = 0
  while true
    nl = buf\find "\n", 1, true
    break unless nl
    line = buf\sub 1, nl - 1
    buf  = buf\sub nl + 1
    continue if #line == 0
    msg, err = decode_msg line
    if msg
      set_pending msg, now_fn
      absorbed += 1
      on_msg msg if on_msg
    else
      log_warn -> { action: "ipc_invalid_message", fd: pipe_rfd, reason: err or "decode_failed", raw: line\sub(1, 180) }
  buf, absorbed

drain_pipe = (pipe_rfd, now_fn, on_msg) ->
  state    = read_states[pipe_rfd] or ""
  absorbed = 0
  while true
    n = libc.read pipe_rfd, read_buf, IPC_READ_CHUNK
    if n == 0
      log_warn -> { action: "ipc_pipe_eof", fd: pipe_rfd }
      break
    if n < 0
      errno_p = libc.__errno_location!
      errno = if errno_p then errno_p[0] else 0
      break if errno == EAGAIN or errno == EWOULDBLOCK
      log_warn -> { action: "ipc_read_failed", fd: pipe_rfd, errno: errno }
      break
    state ..= ffi.string read_buf, n
    if #state > IPC_MAX_LINE * 4
      log_warn -> { action: "ipc_buffer_oversize", fd: pipe_rfd, size: #state }
      state = ""
    state, added = drain_lines pipe_rfd, state, now_fn, on_msg
    absorbed += added
    break if n < IPC_READ_CHUNK
  read_states[pipe_rfd] = state
  absorbed

is_pending = (txid, ip_str, src_port, resolver_ip_str, now_fn) ->
  key   = make_key txid, ip_str, src_port, resolver_ip_str
  entry = pending[key]
  return false unless entry
  if now_fn! > entry.expire
    pending[key] = nil
    return false
  true

get_pending_entry = (txid, ip_str, src_port, resolver_ip_str, now_fn) ->
  key   = make_key txid, ip_str, src_port, resolver_ip_str
  entry = pending[key]
  return nil unless entry
  if now_fn! > entry.expire
    pending[key] = nil
    return nil
  entry

consume = (txid, ip_str, src_port, resolver_ip_str) ->
  pending[make_key txid, ip_str, src_port, resolver_ip_str] = nil

{
  :encode_msg
  :decode_msg
  :write_msg
  :write_refused_msg
  :register_modifier
  :modifier_bit
  :encode_modifiers
  :decode_modifiers
  :drain_pipe
  :is_pending
  :get_pending_entry
  :consume
  :MSG_IPV4
  :MSG_IPV6
  :MSG_IPV4_REFUSED
  :MSG_IPV6_REFUSED
  :make_key
}
