local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local config = require("config")
local log_warn
log_warn = require("log").log_warn
local bit = require("bit")
local runtime_cfg = config.runtime or { }
local nft_cfg = config.nft or { }
local ipc_cfg = config.ipc or { }
local IPC_VERSION = "v1"
local IPC_READ_CHUNK = 2048
local IPC_MAX_LINE = 1024
local IPC_WRITE_RETRY_COUNT = 5
local EAGAIN = 11
local EWOULDBLOCK = 11
local timespec_ptr_t = ffi.typeof("timespec_t[1]")
local read_buf = ffi.new("uint8_t[?]", IPC_READ_CHUNK)
local MSG_IPV4 = 0x41
local MSG_IPV6 = 0x36
local MSG_IPV4_REFUSED = 0x52
local MSG_IPV6_REFUSED = 0x72
local MSG_IPV4_DNSONLY = 0x44
local MSG_IPV6_DNSONLY = 0x64
local MSG_IPV4_ALLOW_IP4 = 0x45
local MSG_IPV6_ALLOW_IP4 = 0x34
local MSG_IPV4_ALLOW_IP6 = 0x61
local MSG_IPV6_ALLOW_IP6 = 0x33
local RESOLVER_IPV6_FLAG = 0x80
local to_hex
to_hex = function(s)
  if not (s and #s > 0) then
    return ""
  end
  return (s:gsub(".", function(c)
    return string.format("%02x", c:byte())
  end))
end
local from_hex
from_hex = function(h)
  if not h or #h == 0 then
    return "", nil
  end
  if (#h % 2) ~= 0 then
    return nil, "hex_odd_length"
  end
  if not (h:match("^[0-9a-fA-F]+$")) then
    return nil, "hex_invalid_chars"
  end
  local out = { }
  for i = 1, #h, 2 do
    out[#out + 1] = string.char(tonumber(h:sub(i, i + 1), 16))
  end
  return table.concat(out), nil
end
local mac2s
mac2s = require("ipparse.l2.ethernet").mac2s
local ip2s
ip2s = require("ipparse.l3.ip").ip2s
local mac_raw_to_str
mac_raw_to_str = function(mac_raw)
  if not (mac_raw and #mac_raw == 6) then
    return "00:00:00:00:00:00"
  end
  return mac2s(mac_raw)
end
local ip_raw_to_str
ip_raw_to_str = function(ip_raw)
  if not (ip_raw and (#ip_raw == 4 or #ip_raw == 16)) then
    return nil
  end
  return ip2s(ip_raw)
end
local is_ipv4_str
is_ipv4_str = function(s)
  return s and s:match("^%d+%.%d+%.%d+%.%d+$")
end
local is_ipv6_str
is_ipv6_str = function(s)
  return s and s:find(":", 1, true)
end
local is_valid_mac
is_valid_mac = function(s)
  return s and s:match("^[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]$")
end
local is_valid_timeout
is_valid_timeout = function(t)
  if not (type(t) == "string") then
    return false
  end
  if not (#t > 0 and #t <= 16) then
    return false
  end
  return t:match("^%d+[smhdw]?$") ~= nil
end
local msg_type_for
msg_type_for = function(ipv4, refused, dnsonly, allow_ip4, allow_ip6)
  if ipv4 then
    if allow_ip4 then
      return MSG_IPV4_ALLOW_IP4
    end
    if allow_ip6 then
      return MSG_IPV4_ALLOW_IP6
    end
    if dnsonly then
      return MSG_IPV4_DNSONLY
    end
    if refused then
      return MSG_IPV4_REFUSED
    end
    return MSG_IPV4
  end
  if allow_ip4 then
    return MSG_IPV6_ALLOW_IP4
  end
  if allow_ip6 then
    return MSG_IPV6_ALLOW_IP6
  end
  if dnsonly then
    return MSG_IPV6_DNSONLY
  end
  if refused then
    return MSG_IPV6_REFUSED
  end
  return MSG_IPV6
end
local write_with_retry
write_with_retry = function(pipe_wfd, msg)
  local sleep_req = timespec_ptr_t()
  for i = 1, IPC_WRITE_RETRY_COUNT do
    local n = libc.write(pipe_wfd, msg, #msg)
    if n == #msg then
      return true
    end
    local errno_p = libc.__errno_location()
    local errno
    if errno_p then
      errno = errno_p[0]
    else
      errno = 0
    end
    if errno ~= EAGAIN and errno ~= EWOULDBLOCK then
      log_warn({
        action = "ipc_write_syscall_failed",
        fd = pipe_wfd,
        errno = errno,
        attempt = i
      })
      return false
    end
    sleep_req[0].tv_sec = 0
    sleep_req[0].tv_nsec = 20000000
    libc.nanosleep(sleep_req, nil)
  end
  local errno_p = libc.__errno_location()
  local errno
  if errno_p then
    errno = errno_p[0]
  else
    errno = 0
  end
  log_warn({
    action = "ipc_write_failed_exhausted",
    fd = pipe_wfd,
    errno = errno,
    attempts = IPC_WRITE_RETRY_COUNT
  })
  return false
end
local encode_msg
encode_msg = function(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, refused, dnsonly, allow_ip4, allow_ip6, reason, benchmark_ms, rule_id, timeout)
  if not (ip_raw and resolver_ip_raw) then
    return nil
  end
  if not ((#ip_raw == 4 or #ip_raw == 16)) then
    return nil
  end
  if not ((#resolver_ip_raw == 4 or #resolver_ip_raw == 16)) then
    return nil
  end
  local ipv4 = #ip_raw == 4
  local msg_type = msg_type_for(ipv4, not not refused, not not dnsonly, not not allow_ip4, not not allow_ip6)
  if #resolver_ip_raw == 16 then
    msg_type = bit.bor(msg_type, RESOLVER_IPV6_FLAG)
  end
  local client_ip = ip_raw_to_str(ip_raw)
  local resolver_ip = ip_raw_to_str(resolver_ip_raw)
  if not (client_ip and resolver_ip) then
    return nil
  end
  timeout = timeout or nft_cfg.ip_timeout or "2m"
  timeout = tostring(timeout)
  if not (is_valid_timeout(timeout)) then
    return nil
  end
  reason = tostring(reason or "")
  rule_id = tostring(rule_id or "")
  if #reason > 63 then
    reason = reason:sub(1, 63)
  end
  if #rule_id > 63 then
    rule_id = rule_id:sub(1, 63)
  end
  local bench = tonumber(benchmark_ms) or 0
  if bench < 0 then
    bench = 0
  end
  bench = math.floor(bench)
  local line = table.concat({
    IPC_VERSION,
    string.format("%02x", msg_type),
    tostring(tonumber(txid) or 0),
    client_ip,
    tostring(tonumber(src_port) or 0),
    resolver_ip,
    mac_raw_to_str(mac_raw),
    to_hex(reason or ""),
    to_hex(rule_id or ""),
    timeout,
    tostring(bench)
  }, "|") .. "\n"
  if #line > IPC_MAX_LINE then
    return nil
  end
  return line
end
local write_msg
write_msg = function(pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout)
  local msg = encode_msg(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, false, false, false, reason, benchmark_ms, rule_id, timeout)
  if not (msg) then
    return false
  end
  return write_with_retry(pipe_wfd, msg)
end
local write_refused_msg
write_refused_msg = function(pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout)
  local msg = encode_msg(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, true, false, false, false, reason, benchmark_ms, rule_id, timeout)
  if not (msg) then
    return false
  end
  return write_with_retry(pipe_wfd, msg)
end
local write_dnsonly_msg
write_dnsonly_msg = function(pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout)
  local msg = encode_msg(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, true, false, false, reason, benchmark_ms, rule_id, timeout)
  if not (msg) then
    return false
  end
  return write_with_retry(pipe_wfd, msg)
end
local write_allow_ip4_msg
write_allow_ip4_msg = function(pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout)
  local msg = encode_msg(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, false, true, false, reason, benchmark_ms, rule_id, timeout)
  if not (msg) then
    return false
  end
  return write_with_retry(pipe_wfd, msg)
end
local write_allow_ip6_msg
write_allow_ip6_msg = function(pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout)
  local msg = encode_msg(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, false, false, true, reason, benchmark_ms, rule_id, timeout)
  if not (msg) then
    return false
  end
  return write_with_retry(pipe_wfd, msg)
end
local split_fields
split_fields = function(line)
  local out = { }
  local i = 1
  while true do
    local j = line:find("|", i, true)
    if j then
      out[#out + 1] = line:sub(i, j - 1)
      i = j + 1
    else
      out[#out + 1] = line:sub(i)
      break
    end
  end
  return out
end
local decode_msg
decode_msg = function(raw)
  if not (raw and #raw > 0) then
    return nil, "empty"
  end
  local line = raw:gsub("\n+$", "")
  local parts = split_fields(line)
  if not (#parts == 11) then
    return nil, "field_count"
  end
  local version = parts[1]
  if not (version == IPC_VERSION) then
    return nil, "version"
  end
  local msg_type_full = tonumber(parts[2], 16)
  if not (msg_type_full) then
    return nil, "msg_type"
  end
  local msg_type = bit.band(msg_type_full, 0x7F)
  local resolver_ipv6 = bit.band(msg_type_full, RESOLVER_IPV6_FLAG) ~= 0
  local txid = tonumber(parts[3])
  local src_port = tonumber(parts[5])
  local benchmark_num = tonumber(parts[11])
  if not (txid and txid >= 0 and txid <= 65535) then
    return nil, "txid"
  end
  if not (src_port and src_port >= 0 and src_port <= 65535) then
    return nil, "src_port"
  end
  if not (benchmark_num and benchmark_num >= 0) then
    benchmark_num = 0
  end
  local ipv4 = (msg_type == MSG_IPV4 or msg_type == MSG_IPV4_REFUSED or msg_type == MSG_IPV4_DNSONLY or msg_type == MSG_IPV4_ALLOW_IP4 or msg_type == MSG_IPV4_ALLOW_IP6)
  if not (ipv4 or msg_type == MSG_IPV6 or msg_type == MSG_IPV6_REFUSED or msg_type == MSG_IPV6_DNSONLY or msg_type == MSG_IPV6_ALLOW_IP4 or msg_type == MSG_IPV6_ALLOW_IP6) then
    return nil, "family"
  end
  local refused = (msg_type == MSG_IPV4_REFUSED or msg_type == MSG_IPV6_REFUSED)
  local dnsonly = (msg_type == MSG_IPV4_DNSONLY or msg_type == MSG_IPV6_DNSONLY)
  local allow_ip4 = (msg_type == MSG_IPV4_ALLOW_IP4 or msg_type == MSG_IPV6_ALLOW_IP4)
  local allow_ip6 = (msg_type == MSG_IPV4_ALLOW_IP6 or msg_type == MSG_IPV6_ALLOW_IP6)
  local ip_str = parts[4]
  local resolver_ip_str = parts[6]
  if not ((ipv4 and is_ipv4_str(ip_str)) or ((not ipv4) and is_ipv6_str(ip_str))) then
    return nil, "ip_client"
  end
  if not ((resolver_ipv6 and is_ipv6_str(resolver_ip_str)) or ((not resolver_ipv6) and is_ipv4_str(resolver_ip_str))) then
    return nil, "ip_resolver"
  end
  local mac_str = parts[7]:lower()
  if not (is_valid_mac(mac_str)) then
    return nil, "mac"
  end
  local reason, reason_err = from_hex(parts[8])
  if reason_err then
    return nil, "reason_" .. tostring(reason_err)
  end
  local rule_id, rule_err = from_hex(parts[9])
  if rule_err then
    return nil, "rule_id_" .. tostring(rule_err)
  end
  local timeout = parts[10]
  if not (is_valid_timeout(timeout)) then
    return nil, "timeout"
  end
  local benchmark_ms
  if benchmark_num > 0 then
    benchmark_ms = benchmark_num
  else
    benchmark_ms = nil
  end
  return {
    txid = txid,
    ip_str = ip_str,
    src_port = src_port,
    resolver_ip_str = resolver_ip_str,
    msg_type = msg_type,
    mac_str = mac_str,
    ipv4 = ipv4,
    refused = refused,
    dnsonly = dnsonly,
    allow_ip4 = allow_ip4,
    allow_ip6 = allow_ip6,
    reason = reason,
    benchmark_ms = benchmark_ms,
    rule_id = rule_id,
    timeout = timeout
  }, nil
end
local pending = { }
local read_states = { }
local make_key
make_key = function(txid, ip_str, src_port, resolver_ip_str)
  return string.format("%04x:%s:%d:%s", txid, ip_str, src_port, resolver_ip_str)
end
local set_pending
set_pending = function(msg, now_fn)
  local key = make_key(msg.txid, msg.ip_str, msg.src_port, msg.resolver_ip_str)
  pending[key] = {
    expire = now_fn() + (ipc_cfg.pending_ttl or 5),
    refused = msg.refused,
    dnsonly = msg.dnsonly,
    allow_ip4 = msg.allow_ip4,
    allow_ip6 = msg.allow_ip6,
    reason = msg.reason,
    benchmark_ms = msg.benchmark_ms,
    rule_id = msg.rule_id,
    timeout = msg.timeout
  }
end
local drain_lines
drain_lines = function(pipe_rfd, buf, now_fn, on_msg)
  local absorbed = 0
  while true do
    local _continue_0 = false
    repeat
      local nl = buf:find("\n", 1, true)
      if not (nl) then
        break
      end
      local line = buf:sub(1, nl - 1)
      buf = buf:sub(nl + 1)
      if #line == 0 then
        _continue_0 = true
        break
      end
      local msg, err = decode_msg(line)
      if msg then
        set_pending(msg, now_fn)
        absorbed = absorbed + 1
        if on_msg then
          on_msg(msg)
        end
      else
        log_warn({
          action = "ipc_invalid_message",
          fd = pipe_rfd,
          reason = err or "decode_failed",
          raw = line:sub(1, 180)
        })
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return buf, absorbed
end
local drain_pipe
drain_pipe = function(pipe_rfd, now_fn, on_msg)
  local state = read_states[pipe_rfd] or ""
  local absorbed = 0
  while true do
    local n = libc.read(pipe_rfd, read_buf, IPC_READ_CHUNK)
    if n == 0 then
      log_warn({
        action = "ipc_pipe_eof",
        fd = pipe_rfd
      })
      break
    end
    if n < 0 then
      local errno_p = libc.__errno_location()
      local errno
      if errno_p then
        errno = errno_p[0]
      else
        errno = 0
      end
      if errno == EAGAIN or errno == EWOULDBLOCK then
        break
      end
      log_warn({
        action = "ipc_read_failed",
        fd = pipe_rfd,
        errno = errno
      })
      break
    end
    state = state .. ffi.string(read_buf, n)
    if #state > IPC_MAX_LINE * 4 then
      log_warn({
        action = "ipc_buffer_oversize",
        fd = pipe_rfd,
        size = #state
      })
      state = ""
    end
    local added
    state, added = drain_lines(pipe_rfd, state, now_fn, on_msg)
    absorbed = absorbed + added
    if n < IPC_READ_CHUNK then
      break
    end
  end
  read_states[pipe_rfd] = state
  return absorbed
end
local is_pending
is_pending = function(txid, ip_str, src_port, resolver_ip_str, now_fn)
  local key = make_key(txid, ip_str, src_port, resolver_ip_str)
  local entry = pending[key]
  if not (entry) then
    return false
  end
  if now_fn() > entry.expire then
    pending[key] = nil
    return false
  end
  return true
end
local get_pending_entry
get_pending_entry = function(txid, ip_str, src_port, resolver_ip_str, now_fn)
  local key = make_key(txid, ip_str, src_port, resolver_ip_str)
  local entry = pending[key]
  if not (entry) then
    return nil
  end
  if now_fn() > entry.expire then
    pending[key] = nil
    return nil
  end
  return entry
end
local consume
consume = function(txid, ip_str, src_port, resolver_ip_str)
  local key = make_key(txid, ip_str, src_port, resolver_ip_str)
  pending[key] = nil
end
return {
  encode_msg = encode_msg,
  decode_msg = decode_msg,
  write_msg = write_msg,
  write_refused_msg = write_refused_msg,
  write_dnsonly_msg = write_dnsonly_msg,
  write_allow_ip4_msg = write_allow_ip4_msg,
  write_allow_ip6_msg = write_allow_ip6_msg,
  drain_pipe = drain_pipe,
  is_pending = is_pending,
  get_pending_entry = get_pending_entry,
  consume = consume,
  MSG_IPV4 = MSG_IPV4,
  MSG_IPV6 = MSG_IPV6,
  MSG_IPV4_REFUSED = MSG_IPV4_REFUSED,
  MSG_IPV6_REFUSED = MSG_IPV6_REFUSED,
  MSG_IPV4_DNSONLY = MSG_IPV4_DNSONLY,
  MSG_IPV6_DNSONLY = MSG_IPV6_DNSONLY,
  MSG_IPV4_ALLOW_IP4 = MSG_IPV4_ALLOW_IP4,
  MSG_IPV6_ALLOW_IP4 = MSG_IPV6_ALLOW_IP4,
  MSG_IPV4_ALLOW_IP6 = MSG_IPV4_ALLOW_IP6,
  MSG_IPV6_ALLOW_IP6 = MSG_IPV6_ALLOW_IP6,
  make_key = make_key
}
