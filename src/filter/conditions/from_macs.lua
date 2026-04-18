return function(cfg)
  return function(macs)
    local _from_mac = require("filter.conditions.from_mac")
    local checkers
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #macs do
        local mac = macs[_index_0]
        _accum_0[_len_0] = (_from_mac(cfg))(mac)
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
      return false, "Not matched by any MAC"
    end
  end
end
