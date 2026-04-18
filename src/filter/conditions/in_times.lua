return function(cfg)
  return function(names)
    local _in_time = require("filter.conditions.in_time")
    local checkers
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #names do
        local name = names[_index_0]
        _accum_0[_len_0] = (_in_time(cfg))(name)
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
      return false, "Not in any time window: " .. tostring(table.concat(names, ', '))
    end
  end
end
