return function(prop)
  return function(cfg)
    return function(names)
      local _match_netlist = require("filter.conditions._match_netlist")(prop)(cfg)
      return function(req)
        for _, name in ipairs(names) do
          local ok = _match_netlist(name)(req)
          if ok then
            return true, "In one of: " .. tostring(table.concat(names, ', '))
          end
        end
        return false, "Not in any of: " .. tostring(table.concat(names, ', '))
      end
    end
  end
end
