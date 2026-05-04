{ :ffi, :libc } = require "ffi_defs"
{ :log_warn } = require "log"
{ :NFT_FAMILY, :NFT_FAMILY6, :NFT_TABLE, :NFT_SET_IP4, :NFT_SET_IP6, :NFT_SET_MAC4, :NFT_SET_MAC6, :NFT_IP_TIMEOUT } = require "config"

PIPE_BUF_SAFE = 512
IPC_WRITE_RETRY_COUNT = 3
EAGAIN = 11
EWOULDBLOCK = 11

pipe_wfd = nil
sleep_req = ffi.new "timespec_t[1]"

set_wfd = (wfd) ->
  pipe_wfd = wfd

sleep_ms = (ms) ->
  sleep_req[0].tv_sec = math.floor ms / 1000
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  libc.nanosleep sleep_req, nil

write_line = (line) ->
  return false unless pipe_wfd
  return false if #line > PIPE_BUF_SAFE
  for i = 1, IPC_WRITE_RETRY_COUNT
    n = libc.write pipe_wfd, line, #line
    return true if n == #line
    errno_p = libc.__errno_location!
    errno = if errno_p then errno_p[0] else 0
    if errno != EAGAIN and errno != EWOULDBLOCK
      log_warn { action: "nft_queue_write_failed", errno: errno }
      return false
    sleep_ms 10
  log_warn { action: "nft_queue_write_exhausted" }
  false

enqueue = (kind, key, ip) ->
  return false unless kind and key and ip
  write_line "#{kind}|#{key}|#{ip}\n"

add_ip4 = (client_ip, ip_str) -> enqueue "ip4", client_ip, ip_str
add_ip6 = (client_ip, ip_str) -> enqueue "ip6", client_ip, ip_str
add_mac4 = (mac, ip_str) -> enqueue "mac4", mac, ip_str
add_mac6 = (mac, ip_str) -> enqueue "mac6", mac, ip_str

cmd_for = (kind, key, ip) ->
  if kind == "ip4"
    return "add element #{NFT_FAMILY} #{NFT_TABLE} #{NFT_SET_IP4} { #{key} . #{ip} timeout #{NFT_IP_TIMEOUT} }"
  if kind == "ip6"
    return "add element #{NFT_FAMILY6} #{NFT_TABLE} #{NFT_SET_IP6} { #{key} . #{ip} timeout #{NFT_IP_TIMEOUT} }"
  if kind == "mac4"
    return nil unless NFT_SET_MAC4
    return "add element #{NFT_FAMILY} #{NFT_TABLE} #{NFT_SET_MAC4} { #{key} . #{ip} timeout #{NFT_IP_TIMEOUT} }"
  if kind == "mac6"
    return nil unless NFT_SET_MAC6
    return "add element #{NFT_FAMILY6} #{NFT_TABLE} #{NFT_SET_MAC6} { #{key} . #{ip} timeout #{NFT_IP_TIMEOUT} }"
  nil

{ :set_wfd, :add_ip4, :add_ip6, :add_mac4, :add_mac6, :cmd_for }
