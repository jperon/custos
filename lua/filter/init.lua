local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local compile_rules, _decide, _decide_meta
do
  local _obj_0 = require("filter.rule")
  compile_rules, _decide, _decide_meta = _obj_0.compile_rules, _obj_0.decide, _obj_0.decide_meta
end
local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local inject_localnets
inject_localnets = require("filter.localnets").inject_localnets
local ip_whitelist = require("ip_whitelist")
local config = require("config")
local rules
local auth_cfg_cache
local decision_cfg
local clone
clone = function(v)
  if not (type(v) == "table") then
    return v
  end
  local out = { }
  for k, item in pairs(v) do
    out[k] = clone(item)
  end
  return out
end
local build_filter_cfg
build_filter_cfg = function()
  local root = config.filter or { }
  local cfg = clone(root)
  cfg.nets = cfg.nets or { }
  cfg.macs = cfg.macs or { }
  cfg.times = cfg.times or { }
  cfg.sources = cfg.sources or { }
  cfg.rules = cfg.rules or { }
  cfg.users = cfg.users or { }
  cfg.dest_whitelist = cfg.dest_whitelist or { }
  cfg.allowed_domains = cfg.allowed_domains or { }
  cfg.auth = clone(config.auth or { })
  if #cfg.rules == 0 and #cfg.allowed_domains > 0 then
    cfg.rules = {
      {
        description = "Builtin allowlist domains",
        actions = {
          "allow"
        },
        conditions = {
          {
            to_domains = clone(cfg.allowed_domains)
          }
        }
      },
      {
        description = "Builtin default deny",
        actions = {
          "deny"
        }
      }
    }
  end
  return cfg
end
local load
load = function()
  local cfg = build_filter_cfg()
  if not (cfg) then
    log_warn({
      action = "filter_load_failed",
      err = "invalid runtime config"
    })
    return 
  end
  rules = compile_rules(cfg)
  auth_cfg_cache = cfg.auth
  decision_cfg = cfg.decision or { }
  local whitelist = cfg.dest_whitelist or { }
  inject_localnets(cfg, whitelist)
  ip_whitelist.init(whitelist)
  local n = #rules
  return log_info({
    action = "filter_loaded",
    rules = n,
    dest_whitelist = #whitelist
  })
end
local decide
decide = function(req)
  if not (rules) then
    log_warn({
      action = "filter_not_loaded",
      domain = req and req.domain or "unknown"
    })
    return false, "filter not loaded", nil
  end
  return _decide(rules, req, decision_cfg)
end
local decide_meta
decide_meta = function(req)
  if not (rules) then
    log_warn({
      action = "filter_not_loaded",
      domain = req and req.domain or "unknown"
    })
    return {
      verdict = false,
      reason = "filter not loaded",
      rule_id = nil,
      timeout = nil,
      description = nil
    }
  end
  return _decide_meta(rules, req, decision_cfg)
end
local get_auth_cfg
get_auth_cfg = function()
  return auth_cfg_cache or { }
end
return {
  load = load,
  decide = decide,
  decide_meta = decide_meta,
  get_auth_cfg = get_auth_cfg
}
