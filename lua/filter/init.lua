local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local compile_rules, _decide, _decide_meta, _on_response_for, _run_on_response
do
  local _obj_0 = require("filter.rule")
  compile_rules, _decide, _decide_meta, _on_response_for, _run_on_response = _obj_0.compile_rules, _obj_0.decide, _obj_0.decide_meta, _obj_0.on_response_for, _obj_0.run_on_response
end
local log_info, log_warn, log_debug
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug
end
local inject_localnets
inject_localnets = require("filter.localnets").inject_localnets
local ip_whitelist = require("ip_whitelist")
local config = require("config")
local rules = nil
local auth_cfg_cache = nil
local sni_cfg_cache = nil
local decision_cfg = nil
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
local count_keys
count_keys = function(t)
  if not (type(t) == "table") then
    return 0
  end
  local n = 0
  for _ in pairs(t) do
    n = n + 1
  end
  return n
end
local count_user_entries
count_user_entries = function(userlists)
  if not (type(userlists) == "table") then
    return 0
  end
  local n = 0
  for _, users in pairs(userlists) do
    if type(users) == "table" then
      n = n + #users
    end
  end
  return n
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
  cfg.userlists = cfg.userlists or cfg.users or { }
  cfg.users = cfg.users or cfg.userlists or { }
  cfg.dest_whitelist = cfg.dest_whitelist or { }
  cfg.allowed_domains = cfg.allowed_domains or { }
  cfg.auth = clone(config.auth or { })
  if #cfg.rules == 0 and #cfg.allowed_domains > 0 then
    log_warn(function()
      return {
        action = "filter_rules_missing",
        detail = "falling back to allowlist domains"
      }
    end)
    cfg.rules = {
      {
        description = "Builtin allowlist domains",
        actions = {
          "allow"
        },
        conditions = {
          to_domains = clone(cfg.allowed_domains)
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
    log_warn(function()
      return {
        action = "filter_load_failed",
        err = "invalid runtime config"
      }
    end)
    return 
  end
  local root_rules = #(config.filter and config.filter.rules or { })
  local fallback_builtin = root_rules == 0 and #cfg.rules > 0
  local cfg_meta = config.__meta or { }
  log_debug(function()
    return {
      action = "filter_config_source",
      path = cfg_meta.path or "unknown",
      env_path = cfg_meta.env_path or "",
      external_loaded = cfg_meta.external_loaded and 1 or 0,
      load_error = cfg_meta.load_error or "",
      configured_rules = root_rules,
      effective_rules = #cfg.rules,
      fallback_builtin = fallback_builtin and 1 or 0
    }
  end)
  rules = compile_rules(cfg)
  auth_cfg_cache = cfg.auth
  sni_cfg_cache = cfg.sni
  decision_cfg = cfg.decision or { }
  local whitelist = cfg.dest_whitelist or { }
  inject_localnets(cfg, whitelist)
  ip_whitelist.init(whitelist)
  local n = #rules
  return log_info(function()
    return {
      action = "filter_loaded",
      rules = n,
      dest_whitelist = #whitelist,
      userlists = count_keys(cfg.userlists),
      users = count_user_entries(cfg.userlists)
    }
  end)
end
local decide
decide = function(req)
  if not (rules) then
    log_warn(function()
      return {
        action = "filter_not_loaded",
        domain = req and req.domain or "unknown"
      }
    end)
    return false, "filter not loaded", nil
  end
  return _decide(rules, req, decision_cfg)
end
local decide_meta
decide_meta = function(req)
  if not (rules) then
    log_warn(function()
      return {
        action = "filter_not_loaded",
        domain = req and req.domain or "unknown"
      }
    end)
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
local get_sni_cfg
get_sni_cfg = function()
  return sni_cfg_cache or { }
end
local get_rule_on_response
get_rule_on_response = function(rule_id)
  return _on_response_for(rules, rule_id)
end
local run_on_response
run_on_response = function(rule_id, dns_raw, reason, ctx_extra)
  if ctx_extra == nil then
    ctx_extra = nil
  end
  return _run_on_response(rules, rule_id, dns_raw, reason, ctx_extra)
end
local get_rules
get_rules = function()
  return rules
end
return {
  load = load,
  decide = decide,
  decide_meta = decide_meta,
  get_auth_cfg = get_auth_cfg,
  get_sni_cfg = get_sni_cfg,
  get_rule_on_response = get_rule_on_response,
  run_on_response = run_on_response,
  get_rules = get_rules
}
