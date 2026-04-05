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
local encode_msg
encode_msg = function(txid, ip_raw, src_port)
  local buf = ffi.new("uint8_t[21]")
  buf[0] = #ip_raw == 4 and MSG_IPV4 or MSG_IPV6
  buf[1] = bit.rshift(bit.band(txid, 0xFF00), 8)
  buf[2] = bit.band(txid, 0xFF)
  for i = 1, #ip_raw do
    buf[2 + i] = ip_raw:byte(i)
  end
  buf[19] = bit.rshift(bit.band(src_port, 0xFF00), 8)
  buf[20] = bit.band(src_port, 0xFF)
  return ffi.string(buf, IPC_MSG_SIZE)
end
local write_msg
write_msg = function(pipe_wfd, txid, ip_raw, src_port)
  local msg = encode_msg(txid, ip_raw, src_port)
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
  local ip_str
  if msg_type == MSG_IPV4 then
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
  return {
    txid = txid,
    ip_str = ip_str,
    src_port = src_port,
    msg_type = msg_type
  }
end
local pending = { }
local make_key
make_key = function(txid, ip_str, src_port)
  return string.format("%04x:%s:%d", txid, ip_str, src_port)
end
local drain_pipe
drain_pipe = function(pipe_rfd, now_fn)
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
        pending[key] = now_fn() + IPC_PENDING_TTL
        absorbed = absorbed + 1
      end
    end
  end
  return absorbed
end
local is_pending
is_pending = function(txid, ip_str, src_port, now_fn)
  local key = make_key(txid, ip_str, src_port)
  local expire = pending[key]
  if not (expire) then
    return false
  end
  if now_fn() > expire then
    pending[key] = nil
    return false
  end
  return true
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
  drain_pipe = drain_pipe,
  is_pending = is_pending,
  consume = consume,
  MSG_IPV4 = MSG_IPV4,
  MSG_IPV6 = MSG_IPV6,
  make_key = make_key
}
