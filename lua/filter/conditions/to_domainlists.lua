return function(cfg)
  return function(listnames)
    local _to_domainlist = require("filter.conditions.to_domainlist")
    local checkers
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #listnames do
        local name = listnames[_index_0]
        _accum_0[_len_0] = (_to_domainlist(cfg))(name)
        _len_0 = _len_0 + 1
      end
      checkers = _accum_0
    end
    return function(req)
      for _, c in ipairs(checkers) do
        local ok, msg = c(req)
        if ok then
          return ok, msg
        end
      end
      return false, "Domain not in any of: " .. tostring(table.concat(listnames, ', '))
    end
  end
end
