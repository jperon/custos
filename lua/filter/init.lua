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
local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local rules
local load
load = function()
  package.loaded["filter.config"] = nil
  local ok, cfg = pcall(require, "filter.config")
  if not (ok) then
    log_warn({
      action = "filter_load_failed",
      err = tostring(cfg)
    })
    return 
  end
  rules = compile_rules(cfg)
  local n = #rules
  return log_info({
    action = "filter_loaded",
    rules = n
  })
end
local decide
decide = function(req)
  if not (rules) then
    log_warn({
      action = "filter_not_loaded"
    })
    return false, "filter not loaded"
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
  reload = reload
}
