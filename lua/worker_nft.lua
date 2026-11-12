local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local run_cmd
run_cmd = require("nft").run_cmd
local cmd_for, element_spec, sanitize_timeout, ACK_SIZE
do
  local _obj_0 = require("nft_queue")
  cmd_for, element_spec, sanitize_timeout, ACK_SIZE = _obj_0.cmd_for, _obj_0.element_spec, _obj_0.sanitize_timeout, _obj_0.ACK_SIZE
end
local log_info, log_warn, log_debug, set_action_prefix, level_enabled
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug, set_action_prefix, level_enabled = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug, _obj_0.set_action_prefix, _obj_0.level_enabled
end
local split_fields, from_hex, is_ipv4_str, is_ipv6_str, is_valid_mac, is_valid_timeout
do
  local _obj_0 = require("lib.ipc_hex")
  split_fields, from_hex, is_ipv4_str, is_ipv6_str, is_valid_mac, is_valid_timeout = _obj_0.split_fields, _obj_0.from_hex, _obj_0.is_ipv4_str, _obj_0.is_ipv6_str, _obj_0.is_valid_mac, _obj_0.is_valid_timeout
end
local gc_tune = require("lib.gc_tune")
local BUF_SIZE = 8192
local MAX_BATCH = 64
local EAGAIN = 11
local EWOULDBLOCK = 11
local POLLIN = 1
local LINE_VERSION = "v1"
local CLOCK_MONOTONIC = 1
local SKIP_WINDOW_MAX_S = 5
local CACHE_STALE_S = SKIP_WINDOW_MAX_S
local CACHE_MAX_ENTRIES = 4096
local TIMEOUT_UNIT_S = {
  s = 1,
  m = 60,
  h = 3600,
  d = 86400,
  w = 604800
}
local read_buf = ffi.new("char[?]", BUF_SIZE)
local ack_val = ffi.new("uint64_t[1]")
local poll_fd = ffi.new("struct pollfd[1]")
local ts_req = ffi.new("timespec_t[1]")
local validate_item
validate_item = function(kind, key, ip)
  if kind == "ip4" then
    if not (is_ipv4_str(key) and is_ipv4_str(ip)) then
      return false
    end
  elseif kind == "ip6" then
    if not (is_ipv6_str(key) and is_ipv6_str(ip)) then
      return false
    end
  elseif kind == "mac4" then
    if not (is_valid_mac(key) and is_ipv4_str(ip)) then
      return false
    end
  elseif kind == "mac6" then
    if not (is_valid_mac(key) and is_ipv6_str(ip)) then
      return false
    end
  elseif kind == "sip4" then
    if not (is_ipv4_str(key)) then
      return false
    end
  elseif kind == "sip6" then
    if not (is_ipv6_str(key)) then
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
    has_timeout = is_valid_timeout(parts[6]),
    seq = seq,
    widx = widx,
    corr = corr
  }, nil
end
local send_ack
send_ack = function(ack_wfds, widx, seq)
  if not (widx and widx >= 0) then
    return 
  end
  local wfd = ack_wfds[widx + 1]
  if not (wfd) then
    return 
  end
  ack_val[0] = seq or 0
  return libc.write(wfd, ack_val, ACK_SIZE)
end
local monotonic_s
monotonic_s = function()
  libc.clock_gettime(CLOCK_MONOTONIC, ts_req)
  return tonumber(ts_req[0].tv_sec) + tonumber(ts_req[0].tv_nsec) / 1000000000
end
local timeout_to_seconds
timeout_to_seconds = function(t)
  if not (type(t) == "string") then
    return nil
  end
  local digits, unit = t:match("^(%d+)([smhdw]?)$")
  if not (digits) then
    return nil
  end
  local mult = 1
  if unit and unit ~= "" then
    mult = TIMEOUT_UNIT_S[unit]
    if not (mult) then
      return nil
    end
  end
  return tonumber(digits) * mult
end
local new_cache
new_cache = function(opts)
  opts = opts or { }
  return {
    entries = { },
    size = 0,
    max = opts.max or CACHE_MAX_ENTRIES,
    skipped = 0,
    evicted = 0,
    now = opts.now or monotonic_s
  }
end
local cache_evict
cache_evict = function(cache)
  local now = cache.now()
  for k, e in pairs(cache.entries) do
    if now - e.t >= CACHE_STALE_S then
      cache.entries[k] = nil
      cache.size = cache.size - 1
    end
  end
  if cache.size < cache.max then
    return 
  end
  local target = math.floor(cache.max * 3 / 4)
  while cache.size > target do
    local oldest_k, oldest_t = nil, nil
    for k, e in pairs(cache.entries) do
      if oldest_t == nil or e.t < oldest_t then
        oldest_k, oldest_t = k, e.t
      end
    end
    if not (oldest_k) then
      break
    end
    cache.entries[oldest_k] = nil
    cache.size = cache.size - 1
    cache.evicted = cache.evicted + 1
  end
  return nil
end
local cache_put
cache_put = function(cache, key, timeout_s)
  if not (cache and key) then
    return 
  end
  local now = cache.now()
  local entry = cache.entries[key]
  if entry then
    entry.t = now
    entry.timeout_s = timeout_s
    return 
  end
  if cache.size >= cache.max then
    cache_evict(cache)
  end
  cache.entries[key] = {
    t = now,
    timeout_s = timeout_s
  }
  cache.size = cache.size + 1
  return nil
end
local cache_drop
cache_drop = function(cache, key)
  if not (cache and key and cache.entries[key]) then
    return 
  end
  cache.entries[key] = nil
  cache.size = cache.size - 1
  return nil
end
local cache_clear
cache_clear = function(cache)
  if not (cache) then
    return 
  end
  cache.entries = { }
  cache.size = 0
  return nil
end
local UNCACHEABLE_KINDS = {
  auth_mac = true,
  auth_ip4 = true,
  auth_ip6 = true
}
local UNCACHEABLE_SETS = {
  authenticated_ips = true,
  authenticated_ips6 = true,
  authenticated_macs = true,
  ip4_dest_whitelist = true,
  ip6_dest_whitelist = true
}
local cacheable_set
cacheable_set = function(set_name)
  return not (set_name and UNCACHEABLE_SETS[set_name])
end
local cache_key_of
cache_key_of = function(item)
  if item.cache_key then
    return item.cache_key
  end
  local spec = element_spec(item.kind, item.key, item.ip, item.rule_id, item.timeout)
  if spec then
    item.spec = spec
    local cacheable = not UNCACHEABLE_KINDS[item.kind] and cacheable_set(spec.set_name)
    if cacheable then
      item.cache_key = tostring(spec.family) .. "|" .. tostring(spec.table) .. "|" .. tostring(spec.set_name) .. "|" .. tostring(item.key) .. "|" .. tostring(item.ip)
      item.timeout_s = timeout_to_seconds(item.timeout)
    end
  end
  return item.cache_key
end
local try_add_pending
try_add_pending = function(pending, item, cache)
  local entry_key = tostring(item.kind) .. "|" .. tostring(item.key) .. "|" .. tostring(item.ip) .. "|" .. tostring(item.timeout) .. "|" .. tostring(tostring(item.rule_id))
  if pending[entry_key] then
    return false
  end
  cache_key_of(item)
  if cache and item.has_timeout and item.cache_key and item.timeout_s then
    local entry = cache.entries[item.cache_key]
    if entry and entry.timeout_s then
      local window = math.min(item.timeout_s / 10, SKIP_WINDOW_MAX_S)
      if window > 0 and (cache.now() - entry.t) < window and item.timeout_s <= entry.timeout_s + window then
        cache.skipped = cache.skipped + 1
        return false
      end
    end
  end
  pending[entry_key] = item
  return true
end
local build_batch
build_batch = function(pending)
  local groups = { }
  local order = { }
  local singles = { }
  local items = { }
  local count = 0
  for _, item in pairs(pending) do
    local _continue_0 = false
    repeat
      local spec = item.spec or element_spec(item.kind, item.key, item.ip, item.rule_id, item.timeout)
      if not (spec) then
        _continue_0 = true
        break
      end
      count = count + 1
      local gkey = tostring(spec.family) .. "|" .. tostring(spec.table) .. "|" .. tostring(spec.set_name)
      local group = groups[gkey]
      if not (group) then
        group = {
          family = spec.family,
          table = spec.table,
          set_name = spec.set_name,
          elems = { }
        }
        groups[gkey] = group
        order[#order + 1] = gkey
      end
      group.elems[#group.elems + 1] = spec.elem
      singles[#singles + 1] = "add element " .. tostring(spec.family) .. " " .. tostring(spec.table) .. " " .. tostring(spec.set_name) .. " { " .. tostring(spec.elem) .. " }"
      items[#items + 1] = item
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  local cmds = { }
  for _index_0 = 1, #order do
    local gkey = order[_index_0]
    local g = groups[gkey]
    cmds[#cmds + 1] = "add element " .. tostring(g.family) .. " " .. tostring(g.table) .. " " .. tostring(g.set_name) .. " { " .. tostring(table.concat(g.elems, ", ")) .. " }"
  end
  return {
    cmds = cmds,
    singles = singles,
    items = items,
    count = count
  }
end
local flush_batch
flush_batch = function(pending, ack_queue, ack_wfds, cache)
  local rule11_count = 0
  local rule11_items = { }
  for _, item in pairs(pending) do
    if item.rule_id == "rule_11" then
      rule11_count = rule11_count + 1
      rule11_items[#rule11_items + 1] = tostring(item.kind) .. ":" .. tostring(item.key) .. ">" .. tostring(item.ip)
    end
  end
  local batch = build_batch(pending)
  for k in pairs(pending) do
    pending[k] = nil
  end
  local skipped = cache and cache.skipped or 0
  if batch.count > 0 then
    local cmd = table.concat(batch.cmds, "\n")
    local ok, err = run_cmd(cmd, {
      quiet = true
    })
    if rule11_count > 0 and level_enabled("DEBUG") then
      log_debug(function()
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
      if cache then
        local _list_0 = batch.items
        for _index_0 = 1, #_list_0 do
          local item = _list_0[_index_0]
          local key = cache_key_of(item)
          if key and item.timeout_s then
            cache_put(cache, key, item.timeout_s)
          end
        end
      end
      log_debug(function()
        return {
          action = "batch_ok",
          count = batch.count,
          groups = #batch.cmds,
          acks = #ack_queue,
          skipped = skipped
        }
      end)
    else
      log_warn(function()
        return {
          action = "batch_failed",
          count = batch.count,
          groups = #batch.cmds,
          acks = #ack_queue,
          err = err or "",
          skipped = skipped
        }
      end)
      if cache then
        local _list_0 = batch.items
        for _index_0 = 1, #_list_0 do
          local item = _list_0[_index_0]
          local key = cache_key_of(item)
          if key then
            cache_drop(cache, key)
          end
        end
      end
      for i, line in ipairs(batch.singles) do
        local ok_one, err_one = run_cmd(line, {
          quiet = true
        })
        if ok_one and cache then
          local item = batch.items[i]
          local key = cache_key_of(item)
          if key and item.timeout_s then
            cache_put(cache, key, item.timeout_s)
          end
        end
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
        acks = #ack_queue,
        skipped = skipped
      }
    end)
  end
  local workers_to_ack = { }
  for _index_0 = 1, #ack_queue do
    local ack = ack_queue[_index_0]
    local prev = workers_to_ack[ack.widx]
    local seq = ack.seq or 0
    if prev == nil or seq > prev then
      workers_to_ack[ack.widx] = seq
    end
  end
  for widx, seq in pairs(workers_to_ack) do
    send_ack(ack_wfds, widx, seq)
  end
  for i = #ack_queue, 1, -1 do
    ack_queue[i] = nil
  end
end
local run
run = function(rfd, ack_wfds, cache)
  set_action_prefix("nft_")
  local gc = gc_tune.shared()
  gc.apply()
  ack_wfds = ack_wfds or { }
  cache = cache or new_cache()
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
    gc.guard()
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
            if try_add_pending(pending, item, cache) then
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
          flush_batch(pending, ack_queue, ack_wfds, cache)
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
      flush_batch(pending, ack_queue, ack_wfds, cache)
      pending_count = 0
    end
    if not (batch_full) then
      gc.idle()
    end
  end
end
return {
  run = run,
  parse_line = parse_line,
  flush_batch = flush_batch,
  build_batch = build_batch,
  try_add_pending = try_add_pending,
  split_fields = split_fields,
  from_hex = from_hex,
  new_cache = new_cache,
  cache_put = cache_put,
  cache_drop = cache_drop,
  cache_clear = cache_clear,
  cache_key_of = cache_key_of,
  cacheable_set = cacheable_set,
  timeout_to_seconds = timeout_to_seconds
}
