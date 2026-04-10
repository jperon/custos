return function(prop)
  return function(cfg)
    return function(names)
      local _match_maclist = require("filter.conditions._match_maclist")(prop)(cfg)
      return function(req)
        for _, name in ipairs(names) do
          local ok = _match_maclist(name)(req)
          if ok then
            return true, "In one of: " .. tostring(table.concat(names, ', '))
          end
        end
        return false, "Not in any of: " .. tostring(table.concat(names, ', '))
      end
    end
  end
end
