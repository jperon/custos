local check_admin_session, forbidden_page
do
  local _obj_0 = require("webui.handlers.admin_auth")
  check_admin_session, forbidden_page = _obj_0.check_admin_session, _obj_0.forbidden_page
end
local handle_dashboard
handle_dashboard = require("webui.handlers.dashboard").handle_dashboard
local handle_reload, handle_status
do
  local _obj_0 = require("webui.handlers.system")
  handle_reload, handle_status = _obj_0.handle_reload, _obj_0.handle_status
end
local handle_config_index, handle_config_section_get, handle_config_section_post
do
  local _obj_0 = require("webui.handlers.config")
  handle_config_index, handle_config_section_get, handle_config_section_post = _obj_0.handle_config_index, _obj_0.handle_config_section_get, _obj_0.handle_config_section_post
end
local handle_nets_get, handle_nets_post, handle_macs_get, handle_macs_post, handle_users_get, handle_users_post, handle_times_get, handle_times_post, handle_decision_get, handle_decision_post
do
  local _obj_0 = require("webui.handlers.filter")
  handle_nets_get, handle_nets_post, handle_macs_get, handle_macs_post, handle_users_get, handle_users_post, handle_times_get, handle_times_post, handle_decision_get, handle_decision_post = _obj_0.handle_nets_get, _obj_0.handle_nets_post, _obj_0.handle_macs_get, _obj_0.handle_macs_post, _obj_0.handle_users_get, _obj_0.handle_users_post, _obj_0.handle_times_get, _obj_0.handle_times_post, _obj_0.handle_decision_get, _obj_0.handle_decision_post
end
local handle_rules_list, handle_rules_new_get, handle_rules_new_post, handle_rules_edit_get, handle_rules_edit_post, handle_rules_delete, handle_rules_move
do
  local _obj_0 = require("webui.handlers.rules")
  handle_rules_list, handle_rules_new_get, handle_rules_new_post, handle_rules_edit_get, handle_rules_edit_post, handle_rules_delete, handle_rules_move = _obj_0.handle_rules_list, _obj_0.handle_rules_new_get, _obj_0.handle_rules_new_post, _obj_0.handle_rules_edit_get, _obj_0.handle_rules_edit_post, _obj_0.handle_rules_delete, _obj_0.handle_rules_move
end
local SCALAR_SECTIONS = {
  runtime = true,
  nfqueue = true,
  dns = true,
  nft = true,
  ipc = true,
  clients = true,
  mac_learner = true,
  auth = true,
  doh = true,
  events = true,
  metrics = true,
  rtp = true
}
local dispatch
dispatch = function(req, state)
  local method = req.method
  local path = req.path
  local admin, reason = check_admin_session(req, state)
  if not (admin) then
    if reason == "forbidden" then
      local cookie_val = (require("auth.token")).get_cookie(req.headers.cookie or "", "custos_session")
      local p = (require("auth.token")).verify(cookie_val, state.token_key)
      local user = p and p.user or "?"
      return 403, {
        ["Content-Type"] = "text/html; charset=UTF-8"
      }, forbidden_page(user)
    end
    return 302, {
      ["Location"] = "/login"
    }, ""
  end
  if path == "/admin/" or path == "/admin" then
    return handle_dashboard(req, state)
  end
  if path == "/admin/system/status" then
    return handle_status(req, state)
  end
  if path == "/admin/system/reload" and method == "POST" then
    return handle_reload(req, state)
  end
  if path == "/admin/config/" or path == "/admin/config" then
    return handle_config_index(req, state)
  end
  local m = path:match("^/admin/config/([a-z_]+)$")
  if m and SCALAR_SECTIONS[m] then
    if method == "GET" then
      return handle_config_section_get(req, m, state)
    end
    if method == "POST" then
      return handle_config_section_post(req, m, state)
    end
  end
  if path == "/admin/config/filter/nets" then
    if method == "GET" then
      return handle_nets_get(req, state)
    end
    if method == "POST" then
      return handle_nets_post(req, state)
    end
  end
  if path == "/admin/config/filter/macs" then
    if method == "GET" then
      return handle_macs_get(req, state)
    end
    if method == "POST" then
      return handle_macs_post(req, state)
    end
  end
  if path == "/admin/config/filter/users" then
    if method == "GET" then
      return handle_users_get(req, state)
    end
    if method == "POST" then
      return handle_users_post(req, state)
    end
  end
  if path == "/admin/config/filter/times" then
    if method == "GET" then
      return handle_times_get(req, state)
    end
    if method == "POST" then
      return handle_times_post(req, state)
    end
  end
  if path == "/admin/config/filter/decision" then
    if method == "GET" then
      return handle_decision_get(req, state)
    end
    if method == "POST" then
      return handle_decision_post(req, state)
    end
  end
  if path == "/admin/config/filter" or path == "/admin/config/filter/" then
    return 302, {
      ["Location"] = "/admin/config/filter/rules"
    }, ""
  end
  if path == "/admin/config/filter/rules" then
    return handle_rules_list(req, state)
  end
  if path == "/admin/config/filter/rules/new" then
    if method == "GET" then
      return handle_rules_new_get(req, state)
    end
    if method == "POST" then
      return handle_rules_new_post(req, state)
    end
  end
  local n_str, action = path:match("^/admin/config/filter/rules/(%d+)/([a-z]+)$")
  if n_str and action then
    local n = tonumber(n_str)
    if not (n) then
      return 400, { }, "Numéro de règle invalide"
    end
    if action == "edit" then
      if method == "GET" then
        return handle_rules_edit_get(req, n, state)
      end
      if method == "POST" then
        return handle_rules_edit_post(req, n, state)
      end
    end
    if action == "delete" and method == "POST" then
      return handle_rules_delete(req, n, state)
    end
    if action == "move" and method == "POST" then
      return handle_rules_move(req, n, state)
    end
  end
  return 302, {
    ["Location"] = "/admin/"
  }, ""
end
return {
  dispatch = dispatch
}
