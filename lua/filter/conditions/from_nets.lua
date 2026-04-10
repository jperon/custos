return function(cfg)
  return function(cidrs)
    local _from_net = require("filter.conditions.from_net")
    local checkers
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #cidrs do
        local cidr = cidrs[_index_0]
        _accum_0[_len_0] = (_from_net(cfg))(cidr)
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
      return false, "Not matched by any CIDR"
    end
  end
end
