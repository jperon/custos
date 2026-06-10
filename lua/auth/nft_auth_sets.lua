local config = require("config")
local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local user_qualifies_for_rule, rule_requires_auth
do
  local _obj_0 = require("auth.rule_user")
  user_qualifies_for_rule, rule_requires_auth = _obj_0.user_qualifies_for_rule, _obj_0.rule_requires_auth
end
local rule_id_mod = require("filter.rule_id")
local generate_rule_id = rule_id_mod.generate
local qualifies_for_rule
qualifies_for_rule = function(user, rule)
  local filter_cfg = config.filter or { }
  return user_qualifies_for_rule(user, rule, filter_cfg.userlists or { })
end
local auth_set_names
auth_set_names = function(ip)
  if not (ip and ip ~= "unknown") then
    return "_auth_mac", nil
  end
  if ip:find(":") then
    return "_auth_mac", "_auth_ip6"
  else
    return "_auth_mac", "_auth_ip4"
  end
end
local run_auth_set_op
run_auth_set_op = function(nft_sess, rule_id, mac, ip, op, ttl)
  if ttl == nil then
    ttl = nil
  end
  if not (nft_sess) then
    return 
  end
  local mac_set, ip_set = auth_set_names(ip)
  local timeout
  if ttl then
    timeout = " timeout " .. tostring(ttl) .. "s"
  else
    timeout = ""
  end
  local ok, err = pcall(function()
    nft_sess.run_nft(tostring(op) .. " element bridge dns-filter-bridge " .. tostring(rule_id) .. "_auth_mac { " .. tostring(mac) .. tostring(timeout) .. " }", {
      quiet = true
    })
    if ip_set then
      return nft_sess.run_nft(tostring(op) .. " element bridge dns-filter-bridge " .. tostring(rule_id) .. tostring(ip_set) .. " { " .. tostring(ip) .. tostring(timeout) .. " }", {
        quiet = true
      })
    end
  end)
  if not (ok) then
    log_warn(function()
      return {
        action = "auth_set_" .. tostring(op) .. "_failed",
        rule_id = rule_id,
        mac = mac,
        ip = ip,
        err = tostring(err)
      }
    end)
  end
  return ok
end
local for_qualifying_auth_rules
for_qualifying_auth_rules = function(user, fn)
  local filter_cfg = config.filter or { }
  local rules = filter_cfg.rules or { }
  for idx, rule in ipairs(rules) do
    local _continue_0 = false
    repeat
      if not (rule_requires_auth(rule)) then
        _continue_0 = true
        break
      end
      if not (qualifies_for_rule(user, rule)) then
        _continue_0 = true
        break
      end
      fn(generate_rule_id(rule, idx), rule)
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
end
local refresh_rule_auth_sets
refresh_rule_auth_sets = function(nft_sess, ip, mac, ttl, user)
  return for_qualifying_auth_rules(user, function(rule_id, rule)
    local ok = run_auth_set_op(nft_sess, rule_id, mac, ip, "add", ttl)
    log_info(function()
      if ok then
        return {
          action = "server_auth_set_add_mac",
          rule_id = rule_id,
          mac = mac
        }
      end
    end)
    log_info(function()
      if ok and ip and ip:find(":" == nil and ip ~= "unknown") then
        return {
          action = "server_auth_set_add_ip4",
          rule_id = rule_id,
          ip = ip
        }
      end
    end)
    return log_info(function()
      if ok and ip and (ip:find(":")) and ip ~= "unknown" then
        return {
          action = "server_auth_set_add_ip6",
          rule_id = rule_id,
          ip = ip
        }
      end
    end)
  end)
end
local delete_rule_auth_sets
delete_rule_auth_sets = function(nft_sess, ip, mac, user)
  return for_qualifying_auth_rules(user, function(rule_id, rule)
    return run_auth_set_op(nft_sess, rule_id, mac, ip, "delete")
  end)
end
local refresh_nft
refresh_nft = function(nft_sess, ip, mac, ttl, user)
  if not (nft_sess) then
    return 
  end
  if ip and ip ~= "unknown" then
    nft_sess.add_authenticated(ip, ttl)
  end
  if mac and mac ~= "unknown" then
    return nft_sess.add_authenticated_mac(mac, ttl)
  end
end
return {
  qualifies_for_rule = qualifies_for_rule,
  auth_set_names = auth_set_names,
  run_auth_set_op = run_auth_set_op,
  for_qualifying_auth_rules = for_qualifying_auth_rules,
  refresh_rule_auth_sets = refresh_rule_auth_sets,
  delete_rule_auth_sets = delete_rule_auth_sets,
  refresh_nft = refresh_nft
}
