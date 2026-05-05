local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local log_warn, log_debug
do
  local _obj_0 = require("log")
  log_warn, log_debug = _obj_0.log_warn, _obj_0.log_debug
end
local NFT_FAMILY, NFT_FAMILY6, NFT_TABLE, NFT_SET_IP4, NFT_SET_IP6, NFT_SET_MAC4, NFT_SET_MAC6, NFT_IP_TIMEOUT, NFT_ACK_TIMEOUT_MS
do
  local _obj_0 = require("config")
  NFT_FAMILY, NFT_FAMILY6, NFT_TABLE, NFT_SET_IP4, NFT_SET_IP6, NFT_SET_MAC4, NFT_SET_MAC6, NFT_IP_TIMEOUT, NFT_ACK_TIMEOUT_MS = _obj_0.NFT_FAMILY, _obj_0.NFT_FAMILY6, _obj_0.NFT_TABLE, _obj_0.NFT_SET_IP4, _obj_0.NFT_SET_IP6, _obj_0.NFT_SET_MAC4, _obj_0.NFT_SET_MAC6, _obj_0.NFT_IP_TIMEOUT, _obj_0.NFT_ACK_TIMEOUT_MS
end
local PIPE_BUF_SAFE = 512
local IPC_WRITE_RETRY_COUNT = 3
local EAGAIN = 11
local EWOULDBLOCK = 11
local POLLIN = 1
local pipe_wfd = nil
local ack_rfd = nil
local worker_idx = nil
local seq = 0
local last_enqueued_seq = nil
local sleep_req = ffi.new("timespec_t[1]")
local poll_fds = ffi.new("struct pollfd[1]")
local ack_buf = ffi.new("uint8_t[1]")
local set_wfd
set_wfd = function(wfd)
  pipe_wfd = wfd
end
local set_ack_rfd
set_ack_rfd = function(rfd, idx)
  ack_rfd = rfd
  worker_idx = idx
end
local sleep_ms
sleep_ms = function(ms)
  sleep_req[0].tv_sec = math.floor(ms / 1000)
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  return libc.nanosleep(sleep_req, nil)
end
local write_line
write_line = function(line)
  if not (pipe_wfd) then
    return false
  end
  if #line > PIPE_BUF_SAFE then
    return false
  end
  for i = 1, IPC_WRITE_RETRY_COUNT do
    local n = libc.write(pipe_wfd, line, #line)
    if n == #line then
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
        action = "nft_queue_write_failed",
        fd = pipe_wfd,
        line = line,
        errno = errno
      })
      return false
    end
    sleep_ms(10)
  end
  log_warn({
    action = "nft_queue_write_exhausted",
    fd = pipe_wfd,
    line = line
  })
  return false
end
local enqueue
enqueue = function(kind, key, ip)
  if not (kind and key and ip) then
    return false
  end
  seq = seq + 1
  local line
  if worker_idx then
    line = tostring(kind) .. "|" .. tostring(key) .. "|" .. tostring(ip) .. "|" .. tostring(seq) .. "|" .. tostring(worker_idx) .. "\n"
  else
    line = tostring(kind) .. "|" .. tostring(key) .. "|" .. tostring(ip) .. "\n"
  end
  local ok = write_line(line)
  if ok then
    last_enqueued_seq = seq
  end
  return ok
end
local add_ip4
add_ip4 = function(client_ip, ip_str)
  return enqueue("ip4", client_ip, ip_str)
end
local add_ip6
add_ip6 = function(client_ip, ip_str)
  return enqueue("ip6", client_ip, ip_str)
end
local add_mac4
add_mac4 = function(mac, ip_str)
  return enqueue("mac4", mac, ip_str)
end
local add_mac6
add_mac6 = function(mac, ip_str)
  return enqueue("mac6", mac, ip_str)
end
local get_last_seq
get_last_seq = function()
  local s = last_enqueued_seq
  last_enqueued_seq = nil
  return s
end
local wait_ack
wait_ack = function(pending_seq)
  if not (ack_rfd) then
    return true
  end
  local timeout_ms = NFT_ACK_TIMEOUT_MS or 150
  poll_fds[0].fd = ack_rfd
  poll_fds[0].events = POLLIN
  poll_fds[0].revents = 0
  local rv = libc.poll(poll_fds, 1, timeout_ms)
  if rv > 0 then
    libc.read(ack_rfd, ack_buf, 1)
    return true
  end
  log_warn({
    action = "nft_ack_timeout",
    worker_idx = worker_idx,
    seq = pending_seq,
    timeout_ms = timeout_ms
  })
  return false
end
local cmd_for
cmd_for = function(kind, key, ip)
  if kind == "ip4" then
    return "add element " .. tostring(NFT_FAMILY) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(NFT_SET_IP4) .. " { " .. tostring(key) .. " . " .. tostring(ip) .. " timeout " .. tostring(NFT_IP_TIMEOUT) .. " }"
  end
  if kind == "ip6" then
    return "add element " .. tostring(NFT_FAMILY6) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(NFT_SET_IP6) .. " { " .. tostring(key) .. " . " .. tostring(ip) .. " timeout " .. tostring(NFT_IP_TIMEOUT) .. " }"
  end
  if kind == "mac4" then
    if not (NFT_SET_MAC4) then
      return nil
    end
    return "add element " .. tostring(NFT_FAMILY) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(NFT_SET_MAC4) .. " { " .. tostring(key) .. " . " .. tostring(ip) .. " timeout " .. tostring(NFT_IP_TIMEOUT) .. " }"
  end
  if kind == "mac6" then
    if not (NFT_SET_MAC6) then
      return nil
    end
    return "add element " .. tostring(NFT_FAMILY6) .. " " .. tostring(NFT_TABLE) .. " " .. tostring(NFT_SET_MAC6) .. " { " .. tostring(key) .. " . " .. tostring(ip) .. " timeout " .. tostring(NFT_IP_TIMEOUT) .. " }"
  end
  return nil
end
return {
  set_wfd = set_wfd,
  set_ack_rfd = set_ack_rfd,
  get_last_seq = get_last_seq,
  wait_ack = wait_ack,
  add_ip4 = add_ip4,
  add_ip6 = add_ip6,
  add_mac4 = add_mac4,
  add_mac6 = add_mac6,
  cmd_for = cmd_for
}
