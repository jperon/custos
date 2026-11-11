local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local config = require("config")
local bit = require("bit")
local STDOUT_FILENO = 1
local CLOCK_MONOTONIC = 1
local ts = ffi.new("timespec_t")
local _timing_enabled = false
local _last_write_us = 0
local _timing_start = ffi.new("timespec_t")
local _timing_end = ffi.new("timespec_t")
local LOG_LEVEL_MAP = {
  EMERG = 8,
  ALERT = 7,
  CRIT = 6,
  ERROR = 5,
  WARN = 4,
  NOTICE = 3,
  INFO = 2,
  DEBUG = 1,
  ALLOW = 3,
  BLOCK = 4,
  TRACE = 6
}
local CURRENT_LOG_LEVEL_NUM = LOG_LEVEL_MAP[config.runtime.log_level] or LOG_LEVEL_MAP.INFO
local set_timing
set_timing = function(enabled)
  _timing_enabled = enabled and true or false
  return nil
end
local get_last_write_us
get_last_write_us = function()
  return _last_write_us
end
local monotonic_us
monotonic_us = function()
  libc.clock_gettime(CLOCK_MONOTONIC, _timing_start)
  return tonumber(_timing_start.tv_sec) * 1000000 + math.floor(tonumber(_timing_start.tv_nsec) / 1000)
end
local get_log_level_num
get_log_level_num = function(level)
  return LOG_LEVEL_MAP[level] or 0
end
local level_enabled
level_enabled = function(level)
  return get_log_level_num(level) >= CURRENT_LOG_LEVEL_NUM
end
local RL_IDENTITY_KEYS = {
  "addr",
  "alpn",
  "arg1",
  "arg2",
  "available",
  "backend",
  "bridge",
  "captive_ip4",
  "captive_ip6",
  "cert",
  "cert_cache",
  "cert_file",
  "cert_type",
  "client",
  "client_ip",
  "client_mac",
  "closed",
  "cmd",
  "cn",
  "cname_target",
  "configured",
  "cseq_method",
  "ct",
  "custom_url",
  "dir",
  "direction",
  "domain",
  "dst",
  "dst_ip",
  "env_path",
  "err",
  "errno",
  "events_dir",
  "exit_code",
  "external_loaded",
  "fallback",
  "fallback_builtin",
  "families",
  "file",
  "filter_reason",
  "frame_mac",
  "handle",
  "handshake_done",
  "has_ip",
  "has_mac",
  "hint",
  "host",
  "hostname",
  "hs_type",
  "ifindex",
  "ifname",
  "in_ifindex",
  "inherited",
  "inject_nft",
  "interfaces",
  "ip",
  "ip4",
  "ip6",
  "ip_dst",
  "ip_src",
  "ip_version",
  "ipv4",
  "ipv6",
  "items",
  "key",
  "key_file",
  "kind",
  "known_mac",
  "l4_proto",
  "limit",
  "list",
  "load_error",
  "local_ip",
  "mac",
  "mac_fallback",
  "mac_src",
  "max",
  "media_ip",
  "method",
  "modified",
  "name",
  "nft_compilable",
  "nft_err",
  "nft_failure_policy",
  "nft_outcome",
  "nft_rule_id",
  "ns_enabled",
  "ok",
  "old",
  "packet_mac",
  "path",
  "payload_modified",
  "peer",
  "peer_ip",
  "peer_mac",
  "policy_protocols",
  "port",
  "port_dst",
  "proto",
  "protocol",
  "protocols",
  "qname",
  "qnames",
  "qtype",
  "queue",
  "quic_parser_path",
  "rc",
  "rcode",
  "reason",
  "records",
  "redirect_url4",
  "redirect_url6",
  "refused",
  "reject_mark",
  "resolver",
  "resolver_ip",
  "resolvers",
  "response",
  "ret",
  "rule",
  "rule_id",
  "rules",
  "selected_mac",
  "sessions_file",
  "sip_method",
  "sip_status",
  "sni",
  "source",
  "src",
  "src_ip",
  "ssl_err",
  "target",
  "tlla",
  "transient",
  "type",
  "upstream_ip",
  "upstream_port",
  "url",
  "user",
  "username",
  "verdict",
  "verify_tls",
  "version",
  "vlan",
  "worker",
  "worker_idx"
}
local RL_VOLATILE_KEYS = {
  "ack_workers",
  "acks",
  "addrlen",
  "age_h",
  "ancount",
  "answers",
  "attempt",
  "attempts",
  "avail",
  "body_bytes",
  "bytes",
  "cert_size",
  "client_fd",
  "client_timeout",
  "conditions_compiled",
  "conditions_worker_only",
  "configured_rules",
  "corr",
  "count",
  "decoded_bytes",
  "dest_whitelist",
  "detail",
  "dport",
  "dropped",
  "effective_rules",
  "entries",
  "events_rfd",
  "events_wfd",
  "expires_in_s",
  "family",
  "fd",
  "frames",
  "free_pct",
  "grace",
  "hour",
  "ignored",
  "ipc_fd",
  "ipc_retry_attempts",
  "ipc_retry_wait_ms",
  "key_size",
  "learn_rfd",
  "learn_wfd",
  "len",
  "listen_fd",
  "max_age_hours",
  "max_attempts",
  "min_free_pct",
  "mode",
  "msg",
  "need",
  "new",
  "new_size",
  "parent_pid",
  "payload_len",
  "pid",
  "pkt_id",
  "port_src",
  "pos",
  "query_bytes",
  "question_response_rfd",
  "question_response_wfd",
  "raw",
  "removed",
  "removed_count",
  "resp_bytes",
  "retry_after",
  "rfd",
  "rv",
  "sans_count",
  "sent",
  "seq",
  "size",
  "sock",
  "sockets",
  "sport",
  "src_port",
  "status",
  "timeout",
  "timeout_ms",
  "total",
  "total_rules",
  "ts",
  "ttl",
  "ttl_s",
  "txid",
  "userlists",
  "users",
  "worker_only"
}
local RL_IDENTITY_SET = { }
for _index_0 = 1, #RL_IDENTITY_KEYS do
  local k = RL_IDENTITY_KEYS[_index_0]
  RL_IDENTITY_SET[k] = true
end
local RL_VOLATILE_SET = { }
for _index_0 = 1, #RL_VOLATILE_KEYS do
  local k = RL_VOLATILE_KEYS[_index_0]
  RL_VOLATILE_SET[k] = true
end
local RL_CONFIG = {
  captive_redirect = {
    keys = {
      "ip"
    },
    window = 60
  },
  ALLOW = {
    keys = {
      "mac_src",
      "qname",
      "qtype"
    },
    window = 30
  },
  BLOCK = {
    keys = {
      "mac_src",
      "qname",
      "qtype"
    },
    window = 30
  },
  no_ipv6_for_client = {
    keys = {
      "client"
    },
    window = 120
  },
  no_ipv4_for_client = {
    keys = {
      "client"
    },
    window = 120
  },
  response_dnsonly = {
    keys = {
      "dst_ip",
      "qnames"
    },
    window = 30
  },
  server_login_nonce_rejected = {
    keys = {
      "ip",
      "user",
      "err"
    },
    window = 60
  },
  server_login_plaintext_refused = {
    keys = {
      "ip",
      "user"
    },
    window = 60
  },
  server_login_mac_missing = {
    keys = {
      "ip",
      "mac"
    },
    window = 60
  },
  EMERG = {
    keys = RL_IDENTITY_KEYS,
    window = 10
  },
  ALERT = {
    keys = RL_IDENTITY_KEYS,
    window = 10
  },
  CRIT = {
    keys = RL_IDENTITY_KEYS,
    window = 10
  },
  ERROR = {
    keys = RL_IDENTITY_KEYS,
    window = 10
  },
  WARN = {
    keys = RL_IDENTITY_KEYS,
    window = 60
  },
  NOTICE = {
    keys = RL_IDENTITY_KEYS,
    window = 60
  },
  INFO = {
    keys = RL_IDENTITY_KEYS,
    window = 60
  },
  DEBUG = {
    keys = RL_IDENTITY_KEYS,
    window = 30
  },
  TRACE = {
    keys = RL_IDENTITY_KEYS,
    window = 30
  }
}
local RL_NEVER_LIMIT = {
  dns_benchmark = true,
  log_rl_mmap_failed = true,
  log_rl_saturated = true,
  worker_died = true,
  child_crashed = true,
  worker_started = true,
  worker_stopping = true,
  worker_start = true,
  supervisor_running = true,
  supervisor_sigterm = true,
  supervisor_sighup_reload = true,
  supervisor_sighup_kill = true,
  supervisor_sighup_refork = true,
  supervisor_sighup_forward_auth = true,
  ["dns-filter_start"] = true,
  config_source = true,
  config_external_missing = true,
  server_login_success = true,
  server_password_changed = true,
  server_bye_grace = true,
  server_ping_session_invalidated = true,
  user_session_expired = true,
  user_session_removed = true
}
local RL_SLOTS = 4096
local RL_SLOT_WORDS = 4
local RL_HEADER_WORDS = 2
local RL_HAND_SCAN = 32
local RL_MMAP_WORDS = RL_HEADER_WORDS + RL_SLOTS * RL_SLOT_WORDS
local RL_MMAP_BYTES = RL_MMAP_WORDS * 4
local RL_PROBE_MAX = 8
local PROT_READ = 1
local PROT_WRITE = 2
local MAP_SHARED = 0x01
local _map_anonymous
_map_anonymous = function(arch)
  if arch and arch:match("^mips") then
    return 0x800
  else
    return 0x20
  end
end
local MAP_ANONYMOUS = _map_anonymous(jit and jit.arch)
local _rl_base = nil
local _rl = { }
local _rl_fb_n = 0
local _rl_fb_sat = 0
local _rl_fallback_reason = nil
local _rl_sat_warned = false
local _rl_saved_base = nil
local _ok, _err = pcall(function()
  local ptr = libc.mmap(nil, RL_MMAP_BYTES, bit.bor(PROT_READ, PROT_WRITE), bit.bor(MAP_SHARED, MAP_ANONYMOUS), -1, 0)
  if ptr ~= nil and ptr ~= ffi.cast("void*", -1) then
    _rl_base = ffi.cast("uint32_t*", ptr)
  end
end)
if not (_rl_base) then
  if _ok then
    _rl_fallback_reason = "mmap_returned_MAP_FAILED"
  else
    _rl_fallback_reason = tostring(_err)
  end
end
local _action_prefix = ""
local set_action_prefix
set_action_prefix = function(prefix)
  _action_prefix = prefix or ""
end
local _rl_never_limited
_rl_never_limited = function(action)
  if not (action) then
    return false
  end
  if RL_NEVER_LIMIT[action] then
    return true
  end
  if _action_prefix ~= "" and action:sub(1, #_action_prefix) == _action_prefix then
    if RL_NEVER_LIMIT[action:sub(#_action_prefix + 1)] then
      return true
    end
  end
  return false
end
local _rl_resolve_cfg
_rl_resolve_cfg = function(level, fields)
  local action = fields.action
  if action then
    local cfg = RL_CONFIG[action]
    if cfg then
      return cfg
    end
    if _action_prefix ~= "" and action:sub(1, #_action_prefix) == _action_prefix then
      cfg = RL_CONFIG[action:sub(#_action_prefix + 1)]
      if cfg then
        return cfg
      end
    end
  end
  return RL_CONFIG[level]
end
local rl_fingerprint
rl_fingerprint = function(action_key, fields, keys)
  local fp = action_key
  if keys == nil or keys == RL_IDENTITY_KEYS then
    local names = { }
    for k, v in pairs(fields) do
      if k ~= "action" and not RL_VOLATILE_SET[k] then
        names[#names + 1] = k
      end
    end
    table.sort(names)
    for _index_0 = 1, #names do
      local k = names[_index_0]
      fp = fp .. ("|" .. k .. "=" .. tostring(fields[k]))
    end
  else
    for _index_0 = 1, #keys do
      local k = keys[_index_0]
      fp = fp .. ("|" .. tostring(fields[k]))
    end
  end
  return fp
end
local RL_SEP = { }
for _index_0 = 1, #RL_IDENTITY_KEYS do
  local k = RL_IDENTITY_KEYS[_index_0]
  RL_SEP[k] = "\1" .. k .. "="
end
local _rl_hash_step
_rl_hash_step = function(h, s)
  for i = 1, #s do
    h = bit.tobit(h * 33 + s:byte(i))
  end
  return h
end
local _rl_hash
_rl_hash = function(level, fields, keys)
  local action = fields.action or level
  if not (keys) then
    local cfg = _rl_resolve_cfg(level, fields)
    keys = cfg and cfg.keys
  end
  local h = _rl_hash_step(0, level)
  h = _rl_hash_step(h, "\1")
  h = _rl_hash_step(h, action)
  if keys == nil or keys == RL_IDENTITY_KEYS then
    for k, v in pairs(fields) do
      if k ~= "action" and not RL_VOLATILE_SET[k] then
        local fh = _rl_hash_step(0, (RL_SEP[k] or ("\1" .. k .. "=")))
        fh = _rl_hash_step(fh, tostring(v))
        h = bit.bxor(h, fh)
      end
    end
  else
    for _index_0 = 1, #keys do
      local k = keys[_index_0]
      local v = fields[k]
      if v ~= nil then
        h = _rl_hash_step(h, (RL_SEP[k] or ("\1" .. k .. "=")))
        h = _rl_hash_step(h, tostring(v))
      end
    end
  end
  return h % 4294967296
end
local _rl_reset
_rl_reset = function()
  _rl_sat_warned = false
  if _rl_base then
    for i = 0, RL_MMAP_WORDS - 1 do
      _rl_base[i] = 0
    end
  else
    for k in pairs(_rl) do
      _rl[k] = nil
    end
    _rl_fb_n = 0
    _rl_fb_sat = 0
  end
end
local now
now = function()
  libc.clock_gettime(0, ts)
  return tonumber(ts.tv_sec)
end
local format_line
format_line = function(epoch, pid, level, fields, suppressed)
  local parts = {
    "[" .. tostring(epoch) .. "]",
    "[" .. tostring(pid) .. "]",
    level
  }
  for k, v in pairs(fields) do
    local sv = tostring(v)
    if sv:find(" ") then
      table.insert(parts, tostring(k) .. "=\"" .. tostring(sv) .. "\"")
    else
      table.insert(parts, tostring(k) .. "=" .. tostring(sv))
    end
  end
  if suppressed and suppressed > 0 then
    table.insert(parts, "suppressed=" .. tostring(suppressed))
  end
  return table.concat(parts, " ") .. "\n"
end
local _emit_line
_emit_line = function(level, fields)
  libc.clock_gettime(0, ts)
  local line = format_line(tonumber(ts.tv_sec), tonumber(ffi.C.getpid()), level, fields, 0)
  return libc.write(STDOUT_FILENO, line, #line)
end
local _rl_warn_saturated
_rl_warn_saturated = function()
  if _rl_sat_warned then
    return 
  end
  _rl_sat_warned = true
  return _emit_line("WARN", {
    action = "log_rl_saturated",
    slots = RL_SLOTS,
    probe_max = RL_PROBE_MAX,
    detail = "aucun slot recyclable : messages journalisés sans rate-limiting"
  })
end
local rl_shared
rl_shared = function()
  return _rl_base ~= nil
end
local rl_stats
rl_stats = function()
  if _rl_base then
    return {
      shared = true,
      saturated = tonumber(_rl_base[1]),
      slots = RL_SLOTS
    }
  else
    return {
      shared = false,
      saturated = _rl_fb_sat,
      slots = RL_SLOTS
    }
  end
end
local _rl_force_fallback
_rl_force_fallback = function(enable)
  if enable then
    if not (_rl_base == nil) then
      _rl_saved_base = _rl_base
    end
    _rl_base = nil
  elseif _rl_saved_base then
    _rl_base = _rl_saved_base
    _rl_saved_base = nil
  end
end
local _rl_slot_get
_rl_slot_get = function(index)
  if not (_rl_base) then
    return nil
  end
  local off = RL_HEADER_WORDS + index * RL_SLOT_WORDS
  return {
    hash = tonumber(_rl_base[off]),
    ts = tonumber(_rl_base[off + 1]),
    expires = tonumber(_rl_base[off + 2]),
    count = tonumber(_rl_base[off + 3])
  }
end
local _rl_slot_set
_rl_slot_set = function(index, hash, ts, expires, count)
  if not (_rl_base) then
    return nil
  end
  local off = RL_HEADER_WORDS + index * RL_SLOT_WORDS
  _rl_base[off] = hash
  _rl_base[off + 1] = ts
  _rl_base[off + 2] = expires
  _rl_base[off + 3] = count or 0
end
local check_rl
check_rl = function(level, fields, epoch)
  local action_key = fields.action or level
  if _rl_never_limited(fields.action) then
    return 0
  end
  local cfg = _rl_resolve_cfg(level, fields)
  if not (cfg) then
    return 0
  end
  epoch = epoch or tonumber(ts.tv_sec)
  if _rl_base then
    local h = _rl_hash(level, fields, cfg.keys)
    local base = _rl_base
    local window = cfg.window
    local slot = h % RL_SLOTS
    local oldest_slot = nil
    local oldest_exp = nil
    for _probe = 1, RL_PROBE_MAX do
      local _continue_0 = false
      repeat
        local off = RL_HEADER_WORDS + slot * RL_SLOT_WORDS
        local sh = tonumber(base[off])
        local sts = tonumber(base[off + 1])
        local sexp = tonumber(base[off + 2])
        if not (sh == tonumber(base[off])) then
          slot = (slot + 1) % RL_SLOTS
          _continue_0 = true
          break
        end
        if sts == 0 then
          base[off] = h
          base[off + 1] = epoch
          base[off + 2] = epoch + window
          base[off + 3] = 0
          return 0
        end
        if sh == h then
          if epoch >= sts and epoch < sexp then
            base[off + 3] = tonumber(base[off + 3]) + 1
            return -1
          end
          local old_count = tonumber(base[off + 3])
          base[off + 1] = epoch
          base[off + 2] = epoch + window
          base[off + 3] = 0
          return old_count
        end
        if epoch < sts or epoch >= sexp then
          base[off] = h
          base[off + 1] = epoch
          base[off + 2] = epoch + window
          base[off + 3] = 0
          return 0
        end
        if oldest_exp == nil or sexp < oldest_exp then
          oldest_exp = sexp
          oldest_slot = slot
        end
        slot = (slot + 1) % RL_SLOTS
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
    local hand = oldest_slot or (tonumber(base[0]) % RL_SLOTS)
    for _step = 1, RL_HAND_SCAN do
      local off = RL_HEADER_WORDS + hand * RL_SLOT_WORDS
      local sh = tonumber(base[off])
      local sts = tonumber(base[off + 1])
      local sexp = tonumber(base[off + 2])
      if sh == tonumber(base[off]) and sts ~= 0 and (epoch < sts or epoch >= sexp) then
        base[off] = h
        base[off + 1] = epoch
        base[off + 2] = epoch + window
        base[off + 3] = 0
        base[0] = (hand + 1) % RL_SLOTS
        return 0
      end
      hand = (hand + 1) % RL_SLOTS
    end
    base[0] = hand
    base[1] = tonumber(base[1]) + 1
    _rl_warn_saturated()
    return 0
  else
    local fp = rl_fingerprint(tostring(level) .. "|" .. tostring(action_key), fields, cfg.keys)
    local entry = _rl[fp]
    if entry then
      if epoch >= entry.ts and epoch < entry.expires then
        entry.count = entry.count + 1
        return -1
      end
      local old_count = entry.count
      entry.ts = epoch
      entry.expires = epoch + cfg.window
      entry.count = 0
      return old_count
    else
      if _rl_fb_n >= RL_SLOTS then
        for k, e in pairs(_rl) do
          if epoch < e.ts or epoch >= e.expires then
            _rl[k] = nil
            _rl_fb_n = _rl_fb_n - 1
          end
        end
        if _rl_fb_n >= RL_SLOTS then
          for k in pairs(_rl) do
            _rl[k] = nil
          end
          _rl_fb_n = 0
          _rl_fb_sat = _rl_fb_sat + 1
          _rl_warn_saturated()
        end
      end
      _rl[fp] = {
        ts = epoch,
        expires = epoch + cfg.window,
        count = 0
      }
      _rl_fb_n = _rl_fb_n + 1
      return 0
    end
  end
end
local write_log
write_log = function(level, thunk)
  if get_log_level_num(level) < CURRENT_LOG_LEVEL_NUM then
    return 
  end
  local fields = thunk()
  if not (fields) then
    return 
  end
  if _action_prefix ~= "" and fields.action then
    if not (fields.action:sub(1, #_action_prefix) == _action_prefix) then
      local new_fields = { }
      for k, v in pairs(fields) do
        new_fields[k] = v
      end
      new_fields.action = _action_prefix .. fields.action
      fields = new_fields
    end
  end
  libc.clock_gettime(0, ts)
  local epoch = tonumber(ts.tv_sec)
  local pid = tonumber(ffi.C.getpid())
  local suppressed = check_rl(level, fields)
  if suppressed == -1 then
    return 
  end
  local line = format_line(epoch, pid, level, fields, suppressed)
  if _timing_enabled then
    local t0 = monotonic_us()
    libc.write(STDOUT_FILENO, line, #line)
    libc.clock_gettime(CLOCK_MONOTONIC, _timing_end)
    local t1 = tonumber(_timing_end.tv_sec) * 1000000 + math.floor(tonumber(_timing_end.tv_nsec) / 1000)
    _last_write_us = t1 - t0
  else
    return libc.write(STDOUT_FILENO, line, #line)
  end
end
local log_allow
log_allow = function(thunk)
  return write_log("ALLOW", thunk)
end
local log_block
log_block = function(thunk)
  return write_log("BLOCK", thunk)
end
local log_info
log_info = function(thunk)
  return write_log("INFO", thunk)
end
local log_warn
log_warn = function(thunk)
  return write_log("WARN", thunk)
end
local log_error
log_error = function(thunk)
  return write_log("ERROR", thunk)
end
local log_debug
log_debug = function(thunk)
  return write_log("DEBUG", thunk)
end
local log_trace
log_trace = function(thunk)
  return write_log("TRACE", thunk)
end
if not (_rl_base) then
  _emit_line("WARN", {
    action = "log_rl_mmap_failed",
    reason = _rl_fallback_reason or "unknown",
    rl_shared = 0,
    arch = (jit and jit.arch) or "unknown"
  })
end
return {
  write_log = write_log,
  log_allow = log_allow,
  log_block = log_block,
  log_info = log_info,
  log_warn = log_warn,
  log_error = log_error,
  log_debug = log_debug,
  log_trace = log_trace,
  now = now,
  get_log_level_num = get_log_level_num,
  level_enabled = level_enabled,
  rl_fingerprint = rl_fingerprint,
  set_action_prefix = set_action_prefix,
  RL_CONFIG = RL_CONFIG,
  RL_IDENTITY_KEYS = RL_IDENTITY_KEYS,
  RL_IDENTITY_SET = RL_IDENTITY_SET,
  RL_VOLATILE_KEYS = RL_VOLATILE_KEYS,
  RL_VOLATILE_SET = RL_VOLATILE_SET,
  RL_SLOTS = RL_SLOTS,
  RL_PROBE_MAX = RL_PROBE_MAX,
  MAP_ANONYMOUS = MAP_ANONYMOUS,
  _map_anonymous = _map_anonymous,
  check_rl = check_rl,
  format_line = format_line,
  rl_shared = rl_shared,
  rl_stats = rl_stats,
  _rl_hash = _rl_hash,
  _rl_reset = _rl_reset,
  _rl_never_limited = _rl_never_limited,
  _rl_force_fallback = _rl_force_fallback,
  _rl_slot_get = _rl_slot_get,
  _rl_slot_set = _rl_slot_set,
  set_timing = set_timing,
  get_last_write_us = get_last_write_us
}
