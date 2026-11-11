local log_info, log_warn, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.set_action_prefix
end
set_action_prefix("")
local OBJECT_KEYS = {
  ["section"] = true,
  ["rule_id"] = true,
  ["list"] = true,
  ["name"] = true,
  ["new"] = true,
  ["mac"] = true,
  ["dir"] = true,
  ["rules"] = true,
  ["enabled"] = true,
  ["pid"] = true
}
local MAX_CODE_LEN = 48
local short_code
short_code = function(s)
  local out = tostring(s or "unknown")
  out = out:gsub("[^%w_%-%.]", "_")
  return out:sub(1, MAX_CODE_LEN)
end
local actor
actor = function(req)
  return {
    user = (req and req.admin_user) or "?",
    peer = (req and req.peer_ip) or "unknown"
  }
end
local object_fields
object_fields = function(fields)
  local out = { }
  if fields then
    for k, v in pairs(fields) do
      if OBJECT_KEYS[k] and v ~= nil then
        out[k] = v
      end
    end
  end
  return out
end
local emit_change
emit_change = function(req, action, fields, ok, err)
  local out = actor(req)
  out.action = action
  out.ok = ok and 1 or 0
  for k, v in pairs(object_fields(fields)) do
    out[k] = v
  end
  if not ok and err then
    out.err = short_code(err)
  end
  return log_info(function()
    return out
  end)
end
local change
change = function(req, action, fields)
  emit_change(req, action, fields, true)
  return nil
end
local fail
fail = function(req, action, fields, err)
  emit_change(req, action, fields, false, err)
  return nil
end
local refused
refused = function(req, reason, fields)
  local out = actor(req)
  out.action = "webui_change_refused"
  out.reason = short_code(reason)
  out.ok = 0
  for k, v in pairs(object_fields(fields)) do
    out[k] = v
  end
  log_warn(function()
    return out
  end)
  return nil
end
return {
  change = change,
  fail = fail,
  refused = refused,
  short_code = short_code,
  actor = actor,
  object_fields = object_fields,
  OBJECT_KEYS = OBJECT_KEYS,
  MAX_CODE_LEN = MAX_CODE_LEN
}
