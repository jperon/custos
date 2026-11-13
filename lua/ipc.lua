local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local config = require("config")
local lowmem = require("lib.lowmem")
local log_warn, log_info
do
  local _obj_0 = require("log")
  log_warn, log_info = _obj_0.log_warn, _obj_0.log_info
end
local to_hex, from_hex, split_fields, is_valid_timeout, is_ipv4_str, is_ipv6_str, is_valid_mac
do
  local _obj_0 = require("lib.ipc_hex")
  to_hex, from_hex, split_fields, is_valid_timeout, is_ipv4_str, is_ipv6_str, is_valid_mac = _obj_0.to_hex, _obj_0.from_hex, _obj_0.split_fields, _obj_0.is_valid_timeout, _obj_0.is_ipv4_str, _obj_0.is_ipv6_str, _obj_0.is_valid_mac
end
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
local sleep_req = timespec_ptr_t()
local read_buf = ffi.new("uint8_t[?]", IPC_READ_CHUNK)
local MSG_IPV4 = 0x41
local MSG_IPV6 = 0x36
local MSG_IPV4_REFUSED = 0x52
local MSG_IPV6_REFUSED = 0x72
local RESOLVER_IPV6_FLAG = 0x80
local _registered = { }
local _mod_bits = { }
local _finalized = false
local _finalize
_finalize = function()
  if _finalized then
    return 
  end
  table.sort(_registered)
  for i, name in ipairs(_registered) do
    _mod_bits[name] = bit.lshift(1, (i - 1))
  end
  _finalized = true
end
local register_modifier
register_modifier = function(name)
  for _index_0 = 1, #_registered do
    local existing = _registered[_index_0]
    if existing == name then
      return 
    end
  end
  _registered[#_registered + 1] = name
  _finalized = false
end
local modifier_bit
modifier_bit = function(name)
  if not (_finalized) then
    _finalize()
  end
  return _mod_bits[name] or 0
end
local encode_modifiers
encode_modifiers = function(mods)
  if not (mods) then
    return 0
  end
  if not (_finalized) then
    _finalize()
  end
  local result = 0
  for name, val in pairs(mods) do
    local b = _mod_bits[name]
    if b and val then
      result = bit.bor(result, b)
    end
  end
  return result
end
local decode_modifiers
decode_modifiers = function(bits)
  if not (_finalized) then
    _finalize()
  end
  local result = { }
  for name, b in pairs(_mod_bits) do
    result[name] = bit.band(bits, b) ~= 0
  end
  return result
end
local mac2s
mac2s = require("ipparse.l2.ethernet").mac2s
local ip2s
ip2s = require("ipparse.l3.ip").ip2s
local MAC_STR_MAX = 64
local _mac_str_cache = { }
local _mac_str_n = 0
local mac_raw_to_str
mac_raw_to_str = function(mac_raw)
  if not (mac_raw and #mac_raw == 6) then
    return "00:00:00:00:00:00"
  end
  local hit = _mac_str_cache[mac_raw]
  if hit then
    return hit
  end
  local s = mac2s(mac_raw)
  if _mac_str_n >= MAC_STR_MAX then
    _mac_str_cache = { }
    _mac_str_n = 0
  end
  _mac_str_cache[mac_raw] = s
  _mac_str_n = _mac_str_n + 1
  return s
end
local _HEX2 = { }
local _HEX1 = { }
for i = 0, 255 do
  _HEX2[i] = string.format("%02x", i)
  _HEX1[i] = string.format("%x", i)
end
local ip_raw_to_str
ip_raw_to_str = function(ip_raw)
  if not (ip_raw and (#ip_raw == 4 or #ip_raw == 16)) then
    return nil
  end
  return ip2s(ip_raw)
end
local msg_type_for
msg_type_for = function(ipv4, refused)
  if ipv4 then
    if refused then
      return MSG_IPV4_REFUSED
    end
    return MSG_IPV4
  end
  if refused then
    return MSG_IPV6_REFUSED
  end
  return MSG_IPV6
end
local write_with_retry
write_with_retry = function(pipe_wfd, msg)
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
      log_warn(function()
        return {
          action = "ipc_write_syscall_failed",
          fd = pipe_wfd,
          errno = errno,
          attempt = i
        }
      end)
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
  log_warn(function()
    return {
      action = "ipc_write_failed_exhausted",
      fd = pipe_wfd,
      errno = errno,
      attempts = IPC_WRITE_RETRY_COUNT
    }
  end)
  return false
end
local _saturated = { }
local write_once
write_once = function(pipe_wfd, msg)
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
    log_warn(function()
      return {
        action = "ipc_write_syscall_failed",
        fd = pipe_wfd,
        errno = errno,
        attempt = 1
      }
    end)
  end
  return false
end
local write_with_retry_all
write_with_retry_all = function(pipe_wfd, msg)
  if not (type(pipe_wfd) == "table") then
    return write_with_retry(pipe_wfd, msg)
  end
  local delivered = false
  for _index_0 = 1, #pipe_wfd do
    local fd = pipe_wfd[_index_0]
    local ok = false
    if _saturated[fd] then
      ok = write_once(fd, msg)
      if ok then
        _saturated[fd] = nil
        log_info(function()
          return {
            action = "ipc_write_resumed",
            fd = fd
          }
        end)
      end
    elseif write_with_retry(fd, msg) then
      ok = true
    else
      _saturated[fd] = true
      log_warn(function()
        return {
          action = "ipc_write_saturated",
          ipc_fd = fd
        }
      end)
    end
    if ok then
      delivered = true
    end
  end
  return delivered
end
local encode_msg
encode_msg = function(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, refused, reason, benchmark_ms, rule_id, timeout, modifiers, response_rule_ids, question_proc_ms)
  if response_rule_ids == nil then
    response_rule_ids = nil
  end
  if question_proc_ms == nil then
    question_proc_ms = nil
  end
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
  local msg_type = msg_type_for(ipv4, not not refused)
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
  if #rule_id > 130 then
    rule_id = rule_id:sub(1, 130)
  end
  local bench = tonumber(benchmark_ms) or 0
  if bench < 0 then
    bench = 0
  end
  bench = math.floor(bench)
  local qproc = tonumber(question_proc_ms) or 0
  if qproc < 0 then
    qproc = 0
  end
  qproc = math.floor(qproc)
  local mods_bits = encode_modifiers(modifiers)
  local response_ids_hex = ""
  if type(response_rule_ids) == "table" then
    local response_ids = { }
    for _, rid in ipairs(response_rule_ids) do
      local _continue_0 = false
      repeat
        if #response_ids >= 8 then
          break
        end
        if not (rid and rid ~= "") then
          _continue_0 = true
          break
        end
        response_ids[#response_ids + 1] = tostring(rid)
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
    if #response_ids > 0 then
      response_ids_hex = to_hex(table.concat(response_ids, ","))
    end
  end
  local line = IPC_VERSION .. "|" .. (_HEX2[msg_type] or string.format("%02x", msg_type)) .. "|" .. tostring(tonumber(txid) or 0) .. "|" .. client_ip .. "|" .. tostring(tonumber(src_port) or 0) .. "|" .. resolver_ip .. "|" .. mac_raw_to_str(mac_raw) .. "|" .. to_hex(reason) .. "|" .. to_hex(rule_id) .. "|" .. timeout .. "|" .. (bench == 0 and "0" or tostring(bench)) .. "|" .. (_HEX1[mods_bits] or string.format("%x", mods_bits)) .. "|" .. response_ids_hex .. "|" .. (qproc == 0 and "0" or tostring(qproc)) .. "\n"
  if #line > IPC_MAX_LINE then
    return nil
  end
  return line
end
local write_msg
write_msg = function(pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout, modifiers, response_rule_ids, question_proc_ms)
  if response_rule_ids == nil then
    response_rule_ids = nil
  end
  if question_proc_ms == nil then
    question_proc_ms = nil
  end
  local msg = encode_msg(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, false, reason, benchmark_ms, rule_id, timeout, modifiers, response_rule_ids, question_proc_ms)
  if not (msg) then
    return false
  end
  return write_with_retry_all(pipe_wfd, msg)
end
local write_refused_msg
write_refused_msg = function(pipe_wfd, txid, ip_raw, src_port, mac_raw, resolver_ip_raw, reason, benchmark_ms, rule_id, timeout, modifiers, response_rule_ids, question_proc_ms)
  if response_rule_ids == nil then
    response_rule_ids = nil
  end
  if question_proc_ms == nil then
    question_proc_ms = nil
  end
  local msg = encode_msg(txid, ip_raw, src_port, mac_raw, resolver_ip_raw, true, reason, benchmark_ms, rule_id, timeout, modifiers, response_rule_ids, question_proc_ms)
  if not (msg) then
    return false
  end
  return write_with_retry_all(pipe_wfd, msg)
end
local decode_msg
decode_msg = function(raw)
  if not (raw and #raw > 0) then
    return nil, "empty"
  end
  local line
  if raw:byte(#raw) == 10 then
    line = (raw:gsub("\n+$", ""))
  else
    line = raw
  end
  local parts = split_fields(line)
  if not (#parts >= 11) then
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
  local ipv4 = (msg_type == MSG_IPV4 or msg_type == MSG_IPV4_REFUSED)
  if not (ipv4 or msg_type == MSG_IPV6 or msg_type == MSG_IPV6_REFUSED) then
    return nil, "family"
  end
  local refused = (msg_type == MSG_IPV4_REFUSED or msg_type == MSG_IPV6_REFUSED)
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
  local question_proc_num = tonumber(parts[14])
  local question_proc_ms
  if question_proc_num and question_proc_num > 0 then
    question_proc_ms = question_proc_num
  else
    question_proc_ms = nil
  end
  local mods_hex = parts[12] or "0"
  local mods_bits = tonumber(mods_hex, 16) or 0
  local modifiers = decode_modifiers(mods_bits)
  local response_rule_ids_hex = parts[13] or ""
  local response_rule_ids_csv, ids_err = from_hex(response_rule_ids_hex)
  if ids_err then
    return nil, "response_rule_ids_" .. tostring(ids_err)
  end
  local response_rule_ids = { }
  if response_rule_ids_csv and response_rule_ids_csv ~= "" then
    for rid in response_rule_ids_csv:gmatch("[^,]+") do
      response_rule_ids[#response_rule_ids + 1] = rid
    end
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
    reason = reason,
    benchmark_ms = benchmark_ms,
    question_proc_ms = question_proc_ms,
    rule_id = rule_id,
    timeout = timeout,
    modifiers = modifiers,
    response_rule_ids = response_rule_ids
  }, nil
end
local pending = { }
local read_states = { }
local _pending_head = nil
local _pending_tail = nil
local _pending_size = 0
local _pending_evictions = 0
local _configured_pending_max = tonumber(ipc_cfg.pending_max)
local _pending_max = lowmem.resolve_pending_max(_configured_pending_max, lowmem.detect(runtime_cfg))
local make_key
make_key = function(txid, ip_str, src_port, resolver_ip_str)
  return string.format("%04x:%s:%d:%s", txid, ip_str, src_port, resolver_ip_str)
end
local _pending_meta_fields = {
  "refused",
  "rule_id",
  "reason",
  "timeout"
}
local PENDING_CONFLICT_REASON = "ipc_pending_conflict"
local _pending_modifiers_equal
_pending_modifiers_equal = function(a, b)
  a = a or { }
  b = b or { }
  for k, v in pairs(a) do
    if b[k] ~= v then
      return false
    end
  end
  for k, v in pairs(b) do
    if a[k] ~= v then
      return false
    end
  end
  return true
end
local _pending_ids_equal
_pending_ids_equal = function(a, b)
  a = a or { }
  b = b or { }
  if #a ~= #b then
    return false
  end
  for i = 1, #a do
    if a[i] ~= b[i] then
      return false
    end
  end
  return true
end
local pending_meta_diverges
pending_meta_diverges = function(a, b)
  for _index_0 = 1, #_pending_meta_fields do
    local name = _pending_meta_fields[_index_0]
    if a[name] ~= b[name] then
      return true
    end
  end
  if not (_pending_modifiers_equal(a.modifiers, b.modifiers)) then
    return true
  end
  if not (_pending_ids_equal(a.response_rule_ids, b.response_rule_ids)) then
    return true
  end
  return false
end
local _adopt_refused
_adopt_refused = function(entry, msg)
  entry.refused = true
  entry.rule_id = msg.rule_id
  entry.reason = msg.reason
  entry.timeout = msg.timeout
  entry.modifiers = msg.modifiers
  entry.response_rule_ids = msg.response_rule_ids or { }
  return nil
end
local _most_restrictive
_most_restrictive = function(entry, msg)
  if entry.refused then
    return "kept_refused"
  elseif msg.refused then
    _adopt_refused(entry, msg)
    return "adopted_refused"
  else
    entry.refused = true
    entry.reason = PENDING_CONFLICT_REASON
    return "kept_allowed_conflict"
  end
end
local _unlink_pending_node
_unlink_pending_node = function(node)
  local prev, nxt = node.prev, node.next
  if prev then
    prev.next = nxt
  else
    _pending_head = nxt
  end
  if nxt then
    nxt.prev = prev
  else
    _pending_tail = prev
  end
  node.prev = nil
  node.next = nil
end
local _append_pending_node
_append_pending_node = function(key, entry)
  local node = {
    key = key,
    entry = entry,
    prev = _pending_tail,
    next = nil
  }
  if _pending_tail then
    _pending_tail.next = node
  else
    _pending_head = node
  end
  _pending_tail = node
  entry._pending_node = node
  return node
end
local _move_pending_node_to_tail
_move_pending_node_to_tail = function(node)
  if _pending_tail == node then
    return 
  end
  _unlink_pending_node(node)
  node.prev = _pending_tail
  node.next = nil
  if _pending_tail then
    _pending_tail.next = node
  else
    _pending_head = node
  end
  _pending_tail = node
end
local _remove_pending
_remove_pending = function(key)
  local entry = pending[key]
  if not (entry) then
    return false
  end
  pending[key] = nil
  local node = entry._pending_node
  if node then
    _unlink_pending_node(node)
    entry._pending_node = nil
  end
  _pending_size = _pending_size - 1
  return true
end
local _enforce_pending_max
_enforce_pending_max = function()
  local evicted = 0
  while _pending_size > _pending_max do
    local node = _pending_head
    if not (node) then
      break
    end
    pending[node.key] = nil
    node.entry._pending_node = nil
    _unlink_pending_node(node)
    _pending_size = _pending_size - 1
    _pending_evictions = _pending_evictions + 1
    evicted = evicted + 1
  end
  if evicted > 0 then
    log_warn(function()
      return {
        action = "pending_evicted",
        evicted = evicted,
        entries = _pending_size,
        pending_max = _pending_max
      }
    end)
  end
  return nil
end
local overwrite_pending
overwrite_pending = function(key, entry, msg, now_fn)
  entry.expire = now_fn() + (ipc_cfg.pending_ttl or 5)
  if entry._pending_node then
    _move_pending_node_to_tail(entry._pending_node)
  end
  if not (pending_meta_diverges(entry, msg)) then
    log_info(function()
      return {
        action = "ipc_pending_overwrite",
        key = key,
        txid = string.format("0x%04x", msg.txid),
        client_ip = msg.ip_str,
        client_port = msg.src_port,
        resolver_ip = msg.resolver_ip_str,
        refused = entry.refused and 1 or 0
      }
    end)
    return nil
  end
  local resolution = _most_restrictive(entry, msg)
  log_warn(function()
    return {
      action = "ipc_pending_overwrite_divergent",
      key = key,
      txid = string.format("0x%04x", msg.txid),
      client_ip = msg.ip_str,
      client_port = msg.src_port,
      resolver_ip = msg.resolver_ip_str,
      refused_kept = entry.refused and 1 or 0,
      refused_new = msg.refused and 1 or 0,
      rule_kept = entry.rule_id or "",
      rule_new = msg.rule_id or "",
      resolution = resolution
    }
  end)
  return nil
end
local set_pending
set_pending = function(msg, now_fn)
  local key = make_key(msg.txid, msg.ip_str, msg.src_port, msg.resolver_ip_str)
  local previous = pending[key]
  if previous then
    return overwrite_pending(key, previous, msg, now_fn)
  end
  local entry = {
    expire = now_fn() + (ipc_cfg.pending_ttl or 5),
    refused = msg.refused,
    modifiers = msg.modifiers,
    reason = msg.reason,
    benchmark_ms = msg.benchmark_ms,
    question_proc_ms = msg.question_proc_ms,
    rule_id = msg.rule_id,
    timeout = msg.timeout,
    response_rule_ids = msg.response_rule_ids or { }
  }
  pending[key] = entry
  _append_pending_node(key, entry)
  _pending_size = _pending_size + 1
  _enforce_pending_max()
  return entry
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
        log_warn(function()
          return {
            action = "ipc_invalid_message",
            fd = pipe_rfd,
            reason = err or "decode_failed",
            raw = line:sub(1, 180)
          }
        end)
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
      log_warn(function()
        return {
          action = "ipc_pipe_eof",
          fd = pipe_rfd
        }
      end)
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
      log_warn(function()
        return {
          action = "ipc_read_failed",
          fd = pipe_rfd,
          errno = errno
        }
      end)
      break
    end
    state = state .. ffi.string(read_buf, n)
    if #state > IPC_MAX_LINE * 4 then
      log_warn(function()
        return {
          action = "ipc_buffer_oversize",
          fd = pipe_rfd,
          size = #state
        }
      end)
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
    _remove_pending(key)
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
    _remove_pending(key)
    return nil
  end
  return entry
end
local consume
consume = function(txid, ip_str, src_port, resolver_ip_str)
  return _remove_pending(make_key(txid, ip_str, src_port, resolver_ip_str))
end
local purge_pending
purge_pending = function(now_fn)
  local now = now_fn()
  for key, entry in pairs(pending) do
    if now > entry.expire then
      _remove_pending(key)
    end
  end
end
local pending_stats
pending_stats = function()
  return {
    size = _pending_size,
    evicted = _pending_evictions,
    pending_max = _pending_max
  }
end
return {
  encode_msg = encode_msg,
  decode_msg = decode_msg,
  write_msg = write_msg,
  write_refused_msg = write_refused_msg,
  register_modifier = register_modifier,
  modifier_bit = modifier_bit,
  encode_modifiers = encode_modifiers,
  decode_modifiers = decode_modifiers,
  drain_pipe = drain_pipe,
  set_pending = set_pending,
  is_pending = is_pending,
  get_pending_entry = get_pending_entry,
  consume = consume,
  purge_pending = purge_pending,
  pending_stats = pending_stats,
  MSG_IPV4 = MSG_IPV4,
  MSG_IPV6 = MSG_IPV6,
  MSG_IPV4_REFUSED = MSG_IPV4_REFUSED,
  MSG_IPV6_REFUSED = MSG_IPV6_REFUSED,
  make_key = make_key
}
