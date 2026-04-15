return function(cfg)
  return function(names)
    local _from_userlist = (require("filter.conditions.from_userlist"))(cfg)
    return function(req)
      for _, name in ipairs(names) do
        local ok = (_from_userlist(name))(req)
        if ok then
          return true, "In one of: " .. tostring(table.concat(names, ', '))
        end
      end
      return false, "Not in any of: " .. tostring(table.concat(names, ', '))
    end
  end
end
