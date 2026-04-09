return function(cfg)
  return function(domains)
    local _to_domain = require("filter.conditions.to_domain")
    local checkers
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #domains do
        local d = domains[_index_0]
        _accum_0[_len_0] = (_to_domain(cfg))(d)
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
      return false, "Not matched by any domain"
    end
  end
end
