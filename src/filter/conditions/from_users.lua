return function(cfg)
  return function(users)
    local _from_user = require("filter.conditions.from_user")
    local checkers
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #users do
        local user = users[_index_0]
        _accum_0[_len_0] = (_from_user(cfg))(user)
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
      return false, "Not matched by any user"
    end
  end
end
