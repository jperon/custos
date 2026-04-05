local libc, ffi
do
  local _obj_0 = require("ffi_defs")
  libc, ffi = _obj_0.libc, _obj_0.ffi
end
local ALLOWED_DOMAINS
ALLOWED_DOMAINS = require("config").ALLOWED_DOMAINS
local log_info
log_info = require("log").log_info
local allowed_set = { }
local build_index
build_index = function(domains)
  local t = { }
  for _, d in ipairs(domains) do
    t[d:lower()] = true
  end
  return t
end
allowed_set = build_index(ALLOWED_DOMAINS)
local is_allowed
is_allowed = function(qname)
  local name = qname:lower()
  if allowed_set[name] then
    return true
  end
  local pos = name:find(".", 1, true)
  while pos do
    local suffix = name:sub(pos + 1)
    if allowed_set[suffix] then
      return true
    end
    pos = name:find(".", pos + 1, true)
  end
  return false
end
local reload_requested = false
local sighup_handler = ffi.cast("sighandler_t", function(sig)
  reload_requested = true
end)
libc.signal(1, sighup_handler)
local check_reload
check_reload = function()
  if reload_requested then
    reload_requested = false
    package.loaded["config"] = nil
    local ok, new_cfg = pcall(require, "config")
    if ok then
      allowed_set = build_index(new_cfg.ALLOWED_DOMAINS)
      return log_info({
        action = "allowlist_reloaded",
        count = #new_cfg.ALLOWED_DOMAINS
      })
    else
      return log_info({
        action = "allowlist_reload_failed",
        err = tostring(new_cfg)
      })
    end
  end
end
return {
  is_allowed = is_allowed,
  check_reload = check_reload,
  allowed_set = allowed_set
}
