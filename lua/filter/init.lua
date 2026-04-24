local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local compile_rules, _decide
do
  local _obj_0 = require("filter.rule")
  compile_rules, _decide = _obj_0.compile_rules, _obj_0.decide
end
local load_config
load_config = require("filter.lib.load_config").load_config
local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local inject_localnets
inject_localnets = require("filter.localnets").inject_localnets
local ip_whitelist = require("ip_whitelist")
local DEST_WHITELIST
DEST_WHITELIST = require("config").DEST_WHITELIST
local rules
local config_path = os.getenv("CUSTOS_FILTER_CONFIG") or "/etc/custos/filter.yml"
local set_config_path
set_config_path = function(path)
  config_path = path
end
local load
load = function()
  local cfg, err = load_config(config_path)
  if not (cfg) then
    log_warn({
      action = "filter_load_failed",
      err = err
    })
    return 
  end
  rules = compile_rules(cfg)
  local whitelist
  if DEST_WHITELIST and #DEST_WHITELIST > 0 then
    whitelist = DEST_WHITELIST
  else
    whitelist = cfg.dest_whitelist or { }
  end
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
      action = "filter_not_loaded"
    })
    return false, "filter not loaded", nil
  end
  return _decide(rules, req)
end
local reload_requested = false
local sighup_handler = ffi.cast("sighandler_t", function(sig)
  reload_requested = true
end)
libc.signal(1, sighup_handler)
local reload
reload = function()
  if reload_requested then
    reload_requested = false
    return load()
  end
end
return {
  load = load,
  decide = decide,
  reload = reload,
  set_config_path = set_config_path
}
