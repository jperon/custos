local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local IPC_PENDING_TTL
IPC_PENDING_TTL = require("config").IPC_PENDING_TTL
local log_warn
log_warn = require("log").log_warn
local IPC_MSG_SIZE = 43
local IPC_WRITE_RETRY_COUNT = 5
local EAGAIN = 11
local EWOULDBLOCK = 11
local bit = require("bit")
local AF_INET6 = 10
local ipv6_ntop_buf = ffi.new("char[46]")
local timespec_ptr_t = ffi.typeof("timespec_t[1]")
local MSG_IPV4 = 0x41
local MSG_IPV6 = 0x36
local MSG_IPV4_REFUSED = 0x52
local MSG_IPV6_REFUSED = 0x72
local MSG_IPV4_DNSONLY = 0x44
local MSG_IPV6_DNSONLY = 0x64
local write_with_retry
write_with_retry = function(pipe_wfd, msg)
  local sleep_req = timespec_ptr_t()
  for i = 1, IPC_WRITE_RETRY_COUNT do
    local n = libc.write(pipe_wfd, msg, IPC_MSG_SIZE)
    if n == IPC_MSG_SIZE then
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
encode_msg = function(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, refused, dnsonly)
  local buf = ffi.new("uint8_t[43]")
  if #ip_raw == 4 then
    if dnsonly then
      buf[0] = MSG_IPV4_DNSONLY
    elseif refused then
      buf[0] = MSG_IPV4_REFUSED
    else
      buf[0] = MSG_IPV4
    end
  else
    if dnsonly then
      buf[0] = MSG_IPV6_DNSONLY
    elseif refused then
      buf[0] = MSG_IPV6_REFUSED
    else
      buf[0] = MSG_IPV6
    end
  end
  buf[1] = bit.rshift(bit.band(txid, 0xFF00), 8)
  buf[2] = bit.band(txid, 0xFF)
  for i = 1, #ip_raw do
    buf[2 + i] = ip_raw:byte(i)
  end
  buf[19] = bit.rshift(bit.band(src_port, 0xFF00), 8)
  buf[20] = bit.band(src_port, 0xFF)
  if mac_raw and #mac_raw == 6 then
    for i = 1, 6 do
      buf[20 + i] = mac_raw:byte(i)
    end
  end
  for i = 1, #resolver_ip_raw do
    buf[26 + i] = resolver_ip_raw:byte(i)
  end
  return ffi.string(buf, IPC_MSG_SIZE)
end
local write_msg
write_msg = function(pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw)
  local msg = encode_msg(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, false)
  return write_with_retry(pipe_wfd, msg)
end
local write_refused_msg
write_refused_msg = function(pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw)
  local msg = encode_msg(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, true, false)
  return write_with_retry(pipe_wfd, msg)
end
local write_dnsonly_msg
write_dnsonly_msg = function(pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw)
  local msg = encode_msg(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, true)
  return write_with_retry(pipe_wfd, msg)
end
local decode_msg
decode_msg = function(raw)
  if #raw < IPC_MSG_SIZE then
    return nil
  end
  local msg_type = raw:byte(1)
  local txid = bit.bor(bit.lshift(raw:byte(2), 8), raw:byte(3))
  local src_port = bit.bor(bit.lshift(raw:byte(20), 8), raw:byte(21))
  local ipv4 = (msg_type == MSG_IPV4 or msg_type == MSG_IPV4_REFUSED or msg_type == MSG_IPV4_DNSONLY)
  local refused = (msg_type == MSG_IPV4_REFUSED or msg_type == MSG_IPV6_REFUSED)
  local dnsonly = (msg_type == MSG_IPV4_DNSONLY or msg_type == MSG_IPV6_DNSONLY)
  local ip_str
  if ipv4 then
    ip_str = tostring(raw:byte(4)) .. "." .. tostring(raw:byte(5)) .. "." .. tostring(raw:byte(6)) .. "." .. tostring(raw:byte(7))
  else
    local ip_bytes = ffi.new("uint8_t[16]")
    for i = 0, 15 do
      ip_bytes[i] = raw:byte(4 + i)
    end
    libc.inet_ntop(AF_INET6, ip_bytes, ipv6_ntop_buf, 46)
    ip_str = ffi.string(ipv6_ntop_buf)
  end
  local resolver_ip_str
  if raw:byte(32) == 0 and raw:byte(33) == 0 and raw:byte(34) == 0 and raw:byte(35) == 0 and raw:byte(36) == 0 and raw:byte(37) == 0 and raw:byte(38) == 0 and raw:byte(39) == 0 and raw:byte(40) == 0 and raw:byte(41) == 0 and raw:byte(42) == 0 and raw:byte(43) == 0 then
    resolver_ip_str = tostring(raw:byte(28)) .. "." .. tostring(raw:byte(29)) .. "." .. tostring(raw:byte(30)) .. "." .. tostring(raw:byte(31))
  else
    local resolver_ip_bytes = ffi.new("uint8_t[16]")
    for i = 0, 15 do
      resolver_ip_bytes[i] = raw:byte(28 + i)
    end
    libc.inet_ntop(AF_INET6, resolver_ip_bytes, ipv6_ntop_buf, 46)
    resolver_ip_str = ffi.string(ipv6_ntop_buf)
  end
  local mac_str = string.format("%02x:%02x:%02x:%02x:%02x:%02x", raw:byte(22), raw:byte(23), raw:byte(24), raw:byte(25), raw:byte(26), raw:byte(27))
  return {
    txid = txid,
    ip_str = ip_str,
    src_port = src_port,
    resolver_ip_str = resolver_ip_str,
    msg_type = msg_type,
    mac_str = mac_str,
    ipv4 = ipv4,
    refused = refused,
    dnsonly = dnsonly
  }
end
local pending = { }
local make_key
make_key = function(txid, ip_str, src_port, resolver_ip_str)
  return string.format("%04x:%s:%d:%s", txid, ip_str, src_port, resolver_ip_str)
end
local drain_pipe
drain_pipe = function(pipe_rfd, now_fn, on_msg)
  local buf = ffi.new("uint8_t[?]", IPC_MSG_SIZE)
  local absorbed = 0
  while true do
    local n = libc.read(pipe_rfd, buf, IPC_MSG_SIZE)
    if n <= 0 then
      break
    end
    if n == IPC_MSG_SIZE then
      local raw = ffi.string(buf, IPC_MSG_SIZE)
      local msg = decode_msg(raw)
      if msg then
        local key = make_key(msg.txid, msg.ip_str, msg.src_port, msg.resolver_ip_str)
        pending[key] = {
          expire = now_fn() + IPC_PENDING_TTL,
          refused = msg.refused,
          dnsonly = msg.dnsonly
        }
        absorbed = absorbed + 1
        if on_msg then
          on_msg(msg)
        end
      end
    end
  end
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
  make_key = make_key
}
