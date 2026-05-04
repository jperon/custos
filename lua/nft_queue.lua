local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local log_warn
log_warn = require("log").log_warn
local NFT_FAMILY, NFT_FAMILY6, NFT_TABLE, NFT_SET_IP4, NFT_SET_IP6, NFT_SET_MAC4, NFT_SET_MAC6, NFT_IP_TIMEOUT
do
  local _obj_0 = require("config")
  NFT_FAMILY, NFT_FAMILY6, NFT_TABLE, NFT_SET_IP4, NFT_SET_IP6, NFT_SET_MAC4, NFT_SET_MAC6, NFT_IP_TIMEOUT = _obj_0.NFT_FAMILY, _obj_0.NFT_FAMILY6, _obj_0.NFT_TABLE, _obj_0.NFT_SET_IP4, _obj_0.NFT_SET_IP6, _obj_0.NFT_SET_MAC4, _obj_0.NFT_SET_MAC6, _obj_0.NFT_IP_TIMEOUT
end
local PIPE_BUF_SAFE = 512
local IPC_WRITE_RETRY_COUNT = 3
local EAGAIN = 11
local EWOULDBLOCK = 11
local pipe_wfd = nil
local sleep_req = ffi.new("timespec_t[1]")
local set_wfd
set_wfd = function(wfd)
  pipe_wfd = wfd
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
        errno = errno
      })
      return false
    end
    sleep_ms(10)
  end
  log_warn({
    action = "nft_queue_write_exhausted"
  })
  return false
end
local enqueue
enqueue = function(kind, key, ip)
  if not (kind and key and ip) then
    return false
  end
  return write_line(tostring(kind) .. "|" .. tostring(key) .. "|" .. tostring(ip) .. "\n")
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
  add_ip4 = add_ip4,
  add_ip6 = add_ip6,
  add_mac4 = add_mac4,
  add_mac6 = add_mac6,
  cmd_for = cmd_for
}
