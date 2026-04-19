return function(cfg)
  return function(name)
    local _from_user = (require("filter.conditions.from_user"))(cfg)
    local userlists_cfg = cfg.userlists or { }
    return function(req)
      local userlist = userlists_cfg[name]
      if not (userlist) then
        return false, "User list '" .. tostring(name) .. "' not defined"
      end
      for _index_0 = 1, #userlist do
        local user = userlist[_index_0]
        local ok = (_from_user(user))(req)
        if ok then
          return true, tostring(req.src_ip) .. " in userlist '" .. tostring(name) .. "'"
        end
      end
      return false, "Not in userlist '" .. tostring(name) .. "'"
    end
  end
end
