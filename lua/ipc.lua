local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local IPC_MSG_SIZE, IPC_PENDING_TTL
do
  local _obj_0 = require("config")
  IPC_MSG_SIZE, IPC_PENDING_TTL = _obj_0.IPC_MSG_SIZE, _obj_0.IPC_PENDING_TTL
end
local bit = require("bit")
local MSG_IPV4 = 0x41
local MSG_IPV6 = 0x36
local MSG_IPV4_REFUSED = 0x52
local MSG_IPV6_REFUSED = 0x72
local encode_msg
encode_msg = function(txid, ip_raw, src_port, mac_raw, refused)
  local buf = ffi.new("uint8_t[27]")
  if #ip_raw == 4 then
    buf[0] = refused and MSG_IPV4_REFUSED or MSG_IPV4
  else
    buf[0] = refused and MSG_IPV6_REFUSED or MSG_IPV6
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
  return ffi.string(buf, IPC_MSG_SIZE)
end
local write_msg
write_msg = function(pipe_wfd, txid, ip_raw, src_port, mac_raw)
  local msg = encode_msg(txid, ip_raw, src_port, mac_raw, false)
  local n = libc.write(pipe_wfd, msg, IPC_MSG_SIZE)
  return n == IPC_MSG_SIZE
end
local write_refused_msg
write_refused_msg = function(pipe_wfd, txid, ip_raw, src_port, mac_raw)
  local msg = encode_msg(txid, ip_raw, src_port, mac_raw, true)
  local n = libc.write(pipe_wfd, msg, IPC_MSG_SIZE)
  return n == IPC_MSG_SIZE
end
local decode_msg
decode_msg = function(raw)
  if #raw < IPC_MSG_SIZE then
    return nil
  end
  local msg_type = raw:byte(1)
  local txid = bit.bor(bit.lshift(raw:byte(2), 8), raw:byte(3))
  local src_port = bit.bor(bit.lshift(raw:byte(20), 8), raw:byte(21))
  local ipv4 = (msg_type == MSG_IPV4 or msg_type == MSG_IPV4_REFUSED)
  local refused = (msg_type == MSG_IPV4_REFUSED or msg_type == MSG_IPV6_REFUSED)
  local ip_str
  if ipv4 then
    ip_str = tostring(raw:byte(4)) .. "." .. tostring(raw:byte(5)) .. "." .. tostring(raw:byte(6)) .. "." .. tostring(raw:byte(7))
  else
    local groups
    do
      local _accum_0 = { }
      local _len_0 = 1
      for g = 0, 7 do
        _accum_0[_len_0] = string.format("%x", bit.bor(bit.lshift(raw:byte(4 + g * 2), 8), raw:byte(5 + g * 2)))
        _len_0 = _len_0 + 1
      end
      groups = _accum_0
    end
    ip_str = table.concat(groups, ":")
  end
  local mac_str = string.format("%02x:%02x:%02x:%02x:%02x:%02x", raw:byte(22), raw:byte(23), raw:byte(24), raw:byte(25), raw:byte(26), raw:byte(27))
  return {
    txid = txid,
    ip_str = ip_str,
    src_port = src_port,
    msg_type = msg_type,
    mac_str = mac_str,
    ipv4 = ipv4,
    refused = refused
  }
end
local pending = { }
local make_key
make_key = function(txid, ip_str, src_port)
  return string.format("%04x:%s:%d", txid, ip_str, src_port)
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
        local key = make_key(msg.txid, msg.ip_str, msg.src_port)
        pending[key] = {
          expire = now_fn() + IPC_PENDING_TTL,
          refused = msg.refused
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
is_pending = function(txid, ip_str, src_port, now_fn)
  local key = make_key(txid, ip_str, src_port)
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
get_pending_entry = function(txid, ip_str, src_port, now_fn)
  local key = make_key(txid, ip_str, src_port)
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
consume = function(txid, ip_str, src_port)
  local key = make_key(txid, ip_str, src_port)
  pending[key] = nil
end
return {
  encode_msg = encode_msg,
  decode_msg = decode_msg,
  write_msg = write_msg,
  write_refused_msg = write_refused_msg,
  drain_pipe = drain_pipe,
  is_pending = is_pending,
  get_pending_entry = get_pending_entry,
  consume = consume,
  MSG_IPV4 = MSG_IPV4,
  MSG_IPV6 = MSG_IPV6,
  MSG_IPV4_REFUSED = MSG_IPV4_REFUSED,
  MSG_IPV6_REFUSED = MSG_IPV6_REFUSED,
  make_key = make_key
}
