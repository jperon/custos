local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local log_warn
log_warn = require("log").log_warn
local config = require("config")
local nft_cfg = config.nft or { }
local FAMILY = nft_cfg.family or "bridge"
local FAMILY6 = nft_cfg.family6 or "bridge"
local TABLE = nft_cfg.table or "dns-filter-bridge"
local IP_TIMEOUT = nft_cfg.ip_timeout or "2m"
local ACK_TIMEOUT_MS = nft_cfg.ack_timeout_ms or 150
local PIPE_BUF_SAFE = 512
local IPC_WRITE_RETRY_COUNT = 3
local EAGAIN = 11
local EWOULDBLOCK = 11
local POLLIN = 1
local LINE_VERSION = "v1"
local pipe_wfd = nil
local ack_rfd = nil
local worker_idx = nil
local seq = 0
local last_enqueued_seq = nil
local sleep_req = ffi.new("timespec_t[1]")
local poll_fds = ffi.new("struct pollfd[1]")
local ack_buf = ffi.new("uint8_t[1]")
local drain_buf = ffi.new("uint8_t[64]")
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
local to_hex
to_hex = function(s)
  if not (s and #s > 0) then
    return ""
  end
  return (s:gsub(".", function(c)
    return string.format("%02x", c:byte())
  end))
end
local sanitize_timeout
sanitize_timeout = function(timeout)
  local t
  if timeout == nil then
    t = ""
  else
    t = tostring(timeout)
  end
  if is_valid_timeout(t) then
    return t
  end
  local fallback = IP_TIMEOUT
  if is_valid_timeout(fallback) then
    log_warn(function()
      return {
        action = "nft_queue_timeout_invalid_fallback",
        timeout = t,
        fallback = fallback
      }
    end)
    return fallback
  end
  log_warn(function()
    return {
      action = "nft_queue_timeout_invalid_default",
      timeout = t
    }
  end)
  return "2m"
end
local sleep_ms
sleep_ms = function(ms)
  sleep_req[0].tv_sec = math.floor(ms / 1000)
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  return libc.nanosleep(sleep_req, nil)
end
local set_wfd
set_wfd = function(wfd)
  pipe_wfd = wfd
end
local set_ack_rfd
set_ack_rfd = function(rfd, idx)
  ack_rfd = rfd
  worker_idx = idx
end
local write_line
write_line = function(line)
  if not (pipe_wfd) then
    return false
  end
  if #line > PIPE_BUF_SAFE then
    return false
  end
  for _ = 1, IPC_WRITE_RETRY_COUNT do
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
      log_warn(function()
        return {
          action = "nft_queue_write_failed",
          fd = pipe_wfd,
          errno = errno
        }
      end)
      return false
    end
    sleep_ms(10)
  end
  log_warn(function()
    return {
      action = "nft_queue_write_exhausted",
      fd = pipe_wfd
    }
  end)
  return false
end
local drain_ack
drain_ack = function()
  if not (ack_rfd) then
    return 
  end
  while true do
    local n = libc.read(ack_rfd, drain_buf, 64)
    if not (n and n > 0) then
      break
    end
  end
end
local build_line
build_line = function(kind, key, ip, rule_id, timeout, corr, item_seq, widx)
  return table.concat({
    LINE_VERSION,
    kind,
    key,
    ip,
    to_hex(rule_id or ""),
    timeout,
    tostring(item_seq),
    tostring(widx or -1),
    to_hex(corr or "")
  }, "|") .. "\n"
end
local enqueue
enqueue = function(kind, key, ip, rule_id, timeout, corr)
  if not (kind and key and ip) then
    return false
  end
  timeout = sanitize_timeout(timeout)
  seq = seq + 1
  local line = build_line(kind, key, ip, rule_id, timeout, corr, seq, worker_idx)
  local ok = write_line(line)
  if ok then
    last_enqueued_seq = seq
  end
  return ok
end
local add_ip4
add_ip4 = function(client_ip, ip_str, rule_id, timeout, corr)
  return enqueue("ip4", client_ip, ip_str, rule_id, timeout, corr)
end
local add_ip6
add_ip6 = function(client_ip, ip_str, rule_id, timeout, corr)
  return enqueue("ip6", client_ip, ip_str, rule_id, timeout, corr)
end
local add_mac4
add_mac4 = function(mac, ip_str, rule_id, timeout, corr)
  return enqueue("mac4", mac, ip_str, rule_id, timeout, corr)
end
local add_mac6
add_mac6 = function(mac, ip_str, rule_id, timeout, corr)
  return enqueue("mac6", mac, ip_str, rule_id, timeout, corr)
end
local add_sip4
add_sip4 = function(ip_str, rule_id, timeout, corr)
  return enqueue("sip4", ip_str, ip_str, rule_id, timeout, corr)
end
local add_sip6
add_sip6 = function(ip_str, rule_id, timeout, corr)
  return enqueue("sip6", ip_str, ip_str, rule_id, timeout, corr)
end
local add_auth_mac
add_auth_mac = function(mac, rule_id, timeout, corr)
  return enqueue("auth_mac", mac, "_", rule_id, timeout, corr)
end
local add_auth_ip4
add_auth_ip4 = function(ip, rule_id, timeout, corr)
  return enqueue("auth_ip4", ip, "_", rule_id, timeout, corr)
end
local add_auth_ip6
add_auth_ip6 = function(ip, rule_id, timeout, corr)
  return enqueue("auth_ip6", ip, "_", rule_id, timeout, corr)
end
local send_barrier
send_barrier = function(corr)
  if not (pipe_wfd) then
    return false
  end
  drain_ack()
  seq = seq + 1
  local line = build_line("barrier", "_", "_", "", "0s", corr, seq, worker_idx)
  local ok = write_line(line)
  if ok then
    last_enqueued_seq = seq
  end
  return ok
end
local get_last_seq
get_last_seq = function()
  local s = last_enqueued_seq
  last_enqueued_seq = nil
  return s
end
local wait_ack
wait_ack = function(pending_seq, corr)
  if not (ack_rfd) then
    return false
  end
  local timeout_ms = ACK_TIMEOUT_MS
  poll_fds[0].fd = ack_rfd
  poll_fds[0].events = POLLIN
  poll_fds[0].revents = 0
  local rv = libc.poll(poll_fds, 1, timeout_ms)
  if rv > 0 then
    libc.read(ack_rfd, ack_buf, 1)
    return true
  end
  log_warn(function()
    return {
      action = "nft_ack_timeout",
      worker_idx = worker_idx,
      seq = pending_seq,
      corr = corr or "",
      timeout_ms = timeout_ms
    }
  end)
  return false
end
local sanitize_rule_id
sanitize_rule_id = function(rule_id)
  if not (rule_id) then
    return ""
  end
  local s = tostring(rule_id)
  if #s == 0 then
    return ""
  end
  if #s > 126 then
    s = s:sub(1, 126)
  end
  return s
end
local get_set_name
get_set_name = function(kind, rule_id)
  rule_id = sanitize_rule_id(rule_id)
  if rule_id == "" then
    if kind == "sip4" then
      return "sip_peers"
    end
    if kind == "sip6" then
      return "sip_peers6"
    end
    return nil
  end
  if kind == "auth_mac" then
    return tostring(rule_id) .. "_auth_mac"
  end
  if kind == "auth_ip4" then
    return tostring(rule_id) .. "_auth_ip4"
  end
  if kind == "auth_ip6" then
    return tostring(rule_id) .. "_auth_ip6"
  end
  if kind == "ip4" or kind == "ip6" or kind == "mac4" or kind == "mac6" then
    return tostring(rule_id) .. "_" .. tostring(kind)
  end
  return nil
end
local cmd_lines_for
cmd_lines_for = function(kind, key, ip, rule_id, timeout)
  timeout = sanitize_timeout(timeout)
  local set_name = get_set_name(kind, rule_id)
  if not (set_name) then
    return nil
  end
  local set_names = {
    set_name
  }
  local lines = { }
  for _, name in ipairs(set_names) do
    if kind == "ip4" then
      lines[#lines + 1] = "add element " .. tostring(FAMILY) .. " " .. tostring(TABLE) .. " " .. tostring(name) .. " { " .. tostring(key) .. " . " .. tostring(ip) .. " timeout " .. tostring(timeout) .. " }"
    elseif kind == "ip6" then
      lines[#lines + 1] = "add element " .. tostring(FAMILY6) .. " " .. tostring(TABLE) .. " " .. tostring(name) .. " { " .. tostring(key) .. " . " .. tostring(ip) .. " timeout " .. tostring(timeout) .. " }"
    elseif kind == "mac4" then
      lines[#lines + 1] = "add element " .. tostring(FAMILY) .. " " .. tostring(TABLE) .. " " .. tostring(name) .. " { " .. tostring(key) .. " . " .. tostring(ip) .. " timeout " .. tostring(timeout) .. " }"
    elseif kind == "mac6" then
      lines[#lines + 1] = "add element " .. tostring(FAMILY6) .. " " .. tostring(TABLE) .. " " .. tostring(name) .. " { " .. tostring(key) .. " . " .. tostring(ip) .. " timeout " .. tostring(timeout) .. " }"
    elseif kind == "sip4" then
      lines[#lines + 1] = "add element " .. tostring(FAMILY) .. " " .. tostring(TABLE) .. " " .. tostring(name) .. " { " .. tostring(key) .. " timeout " .. tostring(timeout) .. " }"
    elseif kind == "sip6" then
      lines[#lines + 1] = "add element " .. tostring(FAMILY6) .. " " .. tostring(TABLE) .. " " .. tostring(name) .. " { " .. tostring(key) .. " timeout " .. tostring(timeout) .. " }"
    elseif kind == "auth_mac" then
      lines[#lines + 1] = "add element " .. tostring(FAMILY) .. " " .. tostring(TABLE) .. " " .. tostring(name) .. " { " .. tostring(key) .. " timeout " .. tostring(timeout) .. " }"
    elseif kind == "auth_ip4" then
      lines[#lines + 1] = "add element " .. tostring(FAMILY) .. " " .. tostring(TABLE) .. " " .. tostring(name) .. " { " .. tostring(key) .. " timeout " .. tostring(timeout) .. " }"
    elseif kind == "auth_ip6" then
      lines[#lines + 1] = "add element " .. tostring(FAMILY6) .. " " .. tostring(TABLE) .. " " .. tostring(name) .. " { " .. tostring(key) .. " timeout " .. tostring(timeout) .. " }"
    end
  end
  if #lines == 0 then
    return nil
  end
  return lines
end
local cmd_for
cmd_for = function(kind, key, ip, rule_id, timeout)
  local lines = cmd_lines_for(kind, key, ip, rule_id, timeout)
  if not (lines and #lines > 0) then
    return nil
  end
  return table.concat(lines, "\n")
end
return {
  set_wfd = set_wfd,
  set_ack_rfd = set_ack_rfd,
  get_last_seq = get_last_seq,
  wait_ack = wait_ack,
  drain_ack = drain_ack,
  send_barrier = send_barrier,
  add_ip4 = add_ip4,
  add_ip6 = add_ip6,
  add_mac4 = add_mac4,
  add_mac6 = add_mac6,
  add_sip4 = add_sip4,
  add_sip6 = add_sip6,
  add_auth_mac = add_auth_mac,
  add_auth_ip4 = add_auth_ip4,
  add_auth_ip6 = add_auth_ip6,
  cmd_for = cmd_for,
  cmd_lines_for = cmd_lines_for,
  sanitize_timeout = sanitize_timeout,
  get_set_name = get_set_name,
  sanitize_rule_id = sanitize_rule_id
}
