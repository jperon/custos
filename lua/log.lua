local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local config = require("config")
local bit = require("bit")
local STDOUT_FILENO = 1
local ts = ffi.new("timespec_t")
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
local get_log_level_num
get_log_level_num = function(level)
  return LOG_LEVEL_MAP[level] or 0
end
local RL_CONFIG = {
  captive_probe = {
    keys = {
      "ip",
      "path"
    },
    window = 60
  },
  captive_redirect = {
    keys = {
      "ip",
      "path"
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
  neigh_refreshed = {
    keys = { },
    window = 30
  },
  response_dnsonly = {
    keys = {
      "dst_ip",
      "qnames"
    },
    window = 30
  },
  INFO = {
    keys = {
      "action"
    },
    window = 10
  },
  DEBUG = {
    keys = {
      "action"
    },
    window = 10
  }
}
local _rl = { }
local _action_prefix = ""
local set_action_prefix
set_action_prefix = function(prefix)
  _action_prefix = prefix or ""
end
local check_rl
check_rl = function(level, fields)
  local action_key = fields.action or level
  local cfg = RL_CONFIG[action_key]
  if not (cfg) then
    return 0
  end
  local parts = {
    action_key
  }
  local _list_0 = cfg.keys
  for _index_0 = 1, #_list_0 do
    local k = _list_0[_index_0]
    parts[#parts + 1] = tostring(fields[k] or "")
  end
  local fp = table.concat(parts, "|")
  local epoch = tonumber(ts.tv_sec)
  local entry = _rl[fp]
  if entry then
    if epoch - entry.ts < cfg.window then
      entry.count = entry.count + 1
      return -1
    else
      local old_count = entry.count
      entry.ts = epoch
      entry.count = 0
      return old_count
    end
  else
    _rl[fp] = {
      ts = epoch,
      count = 0
    }
    return 0
  end
end
local now
now = function()
  libc.clock_gettime(0, ts)
  return tonumber(ts.tv_sec)
end
local write_log
write_log = function(level, fields)
  if get_log_level_num(level) < CURRENT_LOG_LEVEL_NUM then
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
  if suppressed > 0 then
    table.insert(parts, "suppressed=" .. tostring(suppressed))
  end
  local line = table.concat(parts, " ") .. "\n"
  return libc.write(STDOUT_FILENO, line, #line)
end
local log_allow
log_allow = function(fields)
  return write_log("ALLOW", fields)
end
local log_block
log_block = function(fields)
  return write_log("BLOCK", fields)
end
local log_info
log_info = function(fields)
  return write_log("INFO", fields)
end
local log_warn
log_warn = function(fields)
  return write_log("WARN", fields)
end
local log_error
log_error = function(fields)
  return write_log("ERROR", fields)
end
local log_debug
log_debug = function(fields)
  return write_log("DEBUG", fields)
end
local log_trace
log_trace = function(fields)
  return write_log("TRACE", fields)
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
  set_action_prefix = set_action_prefix
}
