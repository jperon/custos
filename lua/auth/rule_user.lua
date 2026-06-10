local is_any_wildcard
is_any_wildcard = function(allowed_user)
  return tostring(allowed_user) == "_any"
end
local matches_user
matches_user = function(allowed_user, user)
  return is_any_wildcard(allowed_user) or tostring(allowed_user) == tostring(user)
end
local rule_requires_auth
rule_requires_auth = function(rule)
  if not (rule and rule.conditions) then
    return false
  end
  local conditions = rule.conditions
  local is_array_format = type(conditions[1]) == "table"
  if is_array_format then
    for _, cond in ipairs(conditions) do
      local _continue_0 = false
      repeat
        if not (type(cond) == "table") then
          _continue_0 = true
          break
        end
        if cond.from_users or cond.from_userlists then
          return true
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
  else
    if conditions.from_users or conditions.from_userlists then
      return true
    end
  end
  return false
end
local user_qualifies_for_rule
user_qualifies_for_rule = function(user, rule, userlists_cfg)
  if userlists_cfg == nil then
    userlists_cfg = { }
  end
  if not (rule and rule.conditions) then
    return false
  end
  local conditions = rule.conditions
  local is_array_format = type(conditions[1]) == "table"
  if is_array_format then
    for _, cond in ipairs(conditions) do
      local _continue_0 = false
      repeat
        if not (type(cond) == "table") then
          _continue_0 = true
          break
        end
        for k, v in pairs(cond) do
          if k == "from_users" then
            local users_list
            if type(v) == "table" then
              users_list = v
            else
              users_list = {
                v
              }
            end
            for _, allowed_user in ipairs(users_list) do
              if matches_user(allowed_user, user) then
                return true
              end
            end
            return false
          end
          if k == "from_userlists" then
            local list_names
            if type(v) == "table" then
              list_names = v
            else
              list_names = {
                v
              }
            end
            for _, list_name in ipairs(list_names) do
              local list_users = userlists_cfg[list_name] or { }
              for _, allowed_user in ipairs(list_users) do
                if matches_user(allowed_user, user) then
                  return true
                end
              end
            end
            return false
          end
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
  else
    for k, v in pairs(conditions) do
      if k == "from_users" then
        local users_list
        if type(v) == "table" then
          users_list = v
        else
          users_list = {
            v
          }
        end
        for _, allowed_user in ipairs(users_list) do
          if matches_user(allowed_user, user) then
            return true
          end
        end
        return false
      end
      if k == "from_userlists" then
        local list_names
        if type(v) == "table" then
          list_names = v
        else
          list_names = {
            v
          }
        end
        for _, list_name in ipairs(list_names) do
          local list_users = userlists_cfg[list_name] or { }
          for _, allowed_user in ipairs(list_users) do
            if matches_user(allowed_user, user) then
              return true
            end
          end
          return false
        end
      end
    end
  end
  return true
end
return {
  user_qualifies_for_rule = user_qualifies_for_rule,
  matches_user = matches_user,
  rule_requires_auth = rule_requires_auth
}
