local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local run_cmd
run_cmd = require("nft").run_cmd
local cmd_for, sanitize_timeout
do
  local _obj_0 = require("nft_queue")
  cmd_for, sanitize_timeout = _obj_0.cmd_for, _obj_0.sanitize_timeout
end
local log_info, log_warn, log_debug, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug, _obj_0.set_action_prefix
end
local BUF_SIZE = 8192
local MAX_BATCH = 64
local EAGAIN = 11
local EWOULDBLOCK = 11
local POLLIN = 1
local LINE_VERSION = "v1"
local read_buf = ffi.new("char[?]", BUF_SIZE)
local ack_byte = ffi.new("uint8_t[1]")
ack_byte[0] = 0x01
local poll_fd = ffi.new("struct pollfd[1]")
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
local is_ipv4
is_ipv4 = function(s)
  return s and s:match("^%d+%.%d+%.%d+%.%d+$")
end
local is_ipv6
is_ipv6 = function(s)
  return s and s:find(":", 1, true)
end
local is_mac
is_mac = function(s)
  return s and s:match("^[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]$")
end
local validate_item
validate_item = function(kind, key, ip)
  if kind == "ip4" then
    if not (is_ipv4(key) and is_ipv4(ip)) then
      return false
    end
  elseif kind == "ip6" then
    if not (is_ipv6(key) and is_ipv6(ip)) then
      return false
    end
  elseif kind == "mac4" then
    if not (is_mac(key) and is_ipv4(ip)) then
      return false
    end
  elseif kind == "mac6" then
    if not (is_mac(key) and is_ipv6(ip)) then
      return false
    end
  elseif kind == "sip4" then
    if not (is_ipv4(key)) then
      return false
    end
  elseif kind == "sip6" then
    if not (is_ipv6(key)) then
      return false
    end
  else
    return false
  end
  return true
end
local parse_line
parse_line = function(line)
  local parts = split_fields(line)
  if not (#parts == 9) then
    return nil, "field_count"
  end
  if not (parts[1] == LINE_VERSION) then
    return nil, "version"
  end
  local kind, key, ip = parts[2], parts[3], parts[4]
  if not (validate_item(kind, key, ip)) then
    return nil, "tuple"
  end
  local rule_id, err_rule = from_hex(parts[5])
  if err_rule then
    return nil, "rule_id_" .. tostring(err_rule)
  end
  local timeout = sanitize_timeout(parts[6])
  local seq = tonumber(parts[7])
  if not (seq and seq >= 0) then
    return nil, "seq"
  end
  local widx = tonumber(parts[8])
  if not (widx) then
    return nil, "worker_idx"
  end
  local corr, err_corr = from_hex(parts[9])
  if err_corr then
    return nil, "corr_" .. tostring(err_corr)
  end
  return {
    kind = kind,
    key = key,
    ip = ip,
    rule_id = rule_id,
    timeout = timeout,
    seq = seq,
    widx = widx,
    corr = corr
  }, nil
end
local send_ack
send_ack = function(ack_wfds, widx)
  if not (widx and widx >= 0) then
    return 
  end
  local wfd = ack_wfds[widx + 1]
  if not (wfd) then
    return 
  end
  return libc.write(wfd, ack_byte, 1)
end
local try_add_pending
try_add_pending = function(pending, item)
  local entry_key = tostring(item.kind) .. "|" .. tostring(item.key) .. "|" .. tostring(item.ip) .. "|" .. tostring(item.timeout)
  if pending[entry_key] then
    return false
  end
  pending[entry_key] = item
  return true
end
local flush_batch
flush_batch = function(pending, ack_queue, ack_wfds)
  local lines = { }
  local rule11_count = 0
  local rule11_items = { }
  for _, item in pairs(pending) do
    local cmd = cmd_for(item.kind, item.key, item.ip, item.rule_id, item.timeout)
    if cmd then
      lines[#lines + 1] = cmd
    end
    if item.rule_id == "rule_11" then
      rule11_count = rule11_count + 1
      rule11_items[#rule11_items + 1] = tostring(item.kind) .. ":" .. tostring(item.key) .. ">" .. tostring(item.ip)
    end
  end
  for k in pairs(pending) do
    pending[k] = nil
  end
  if #lines > 0 then
    local cmd = table.concat(lines, "\n")
    local ok, err = run_cmd(cmd, {
      quiet = true
    })
    if rule11_count > 0 then
      log_info(function()
        return {
          action = "nft_batch_rule",
          rule_id = "rule_11",
          count = rule11_count,
          ok = ok,
          items = table.concat(rule11_items, " ")
        }
      end)
    end
    if ok then
      log_debug(function()
        return {
          action = "batch_ok",
          count = #lines,
          acks = #ack_queue
        }
      end)
    else
      log_warn(function()
        return {
          action = "batch_failed",
          count = #lines,
          acks = #ack_queue,
          err = err or ""
        }
      end)
      for _index_0 = 1, #lines do
        local line = lines[_index_0]
        local ok_one, err_one = run_cmd(line, {
          quiet = true
        })
        log_warn(function()
          if not (ok_one) then
            return {
              action = "single_failed",
              err = err_one or "",
              cmd = line
            }
          end
        end)
      end
    end
  else
    log_debug(function()
      return {
        action = "batch_ack_only",
        acks = #ack_queue
      }
    end)
  end
  local workers_to_ack = { }
  for _index_0 = 1, #ack_queue do
    local ack = ack_queue[_index_0]
    workers_to_ack[ack.widx] = true
  end
  for widx, _ in pairs(workers_to_ack) do
    send_ack(ack_wfds, widx)
  end
  for i = #ack_queue, 1, -1 do
    ack_queue[i] = nil
  end
end
local run
run = function(rfd, ack_wfds)
  set_action_prefix("nft_")
  ack_wfds = ack_wfds or { }
  log_info(function()
    return {
      action = "worker_start",
      rfd = rfd,
      ack_workers = #ack_wfds
    }
  end)
  local pending = { }
  local pending_count = 0
  local ack_queue = { }
  local partial = ""
  poll_fd[0].fd = rfd
  poll_fd[0].events = POLLIN
  while true do
    if not (partial:find("\n", 1, true)) then
      poll_fd[0].revents = 0
      libc.poll(poll_fd, 1, -1)
    end
    local batch_full = false
    while not batch_full do
      while true do
        local _continue_0 = false
        repeat
          local nl = partial:find("\n", 1, true)
          if not (nl) then
            break
          end
          local line = partial:sub(1, nl - 1)
          partial = partial:sub(nl + 1)
          if #line == 0 then
            _continue_0 = true
            break
          end
          local item, parse_err = parse_line(line)
          if item then
            ack_queue[#ack_queue + 1] = {
              widx = item.widx,
              seq = item.seq,
              corr = item.corr,
              rule_id = item.rule_id
            }
            if try_add_pending(pending, item) then
              pending_count = pending_count + 1
            end
          else
            log_warn(function()
              return {
                action = "nft_invalid_message",
                reason = parse_err or "parse_failed",
                raw = line:sub(1, 220)
              }
            end)
          end
          if pending_count >= MAX_BATCH then
            batch_full = true
            break
          end
          _continue_0 = true
        until true
        if not _continue_0 then
          break
        end
      end
      if batch_full then
        break
      end
      local n = libc.read(rfd, read_buf, BUF_SIZE)
      if n and n > 0 then
        partial = partial .. ffi.string(read_buf, n)
        if #partial > 4096 and not partial:find("\n", 1, true) then
          log_warn(function()
            return {
              action = "nft_partial_oversize",
              size = #partial
            }
          end)
          partial = ""
        end
      elseif n == 0 then
        if pending_count > 0 or #ack_queue > 0 then
          flush_batch(pending, ack_queue, ack_wfds)
        end
        log_warn(function()
          return {
            action = "pipe_closed",
            rfd = rfd
          }
        end)
        return 
      else
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
        log_warn(function()
          return {
            action = "read_failed",
            rfd = rfd,
            errno = errno
          }
        end)
        break
      end
    end
    if pending_count > 0 or #ack_queue > 0 then
      flush_batch(pending, ack_queue, ack_wfds)
      pending_count = 0
    end
  end
end
return {
  run = run,
  parse_line = parse_line,
  flush_batch = flush_batch,
  try_add_pending = try_add_pending,
  split_fields = split_fields,
  from_hex = from_hex
}
