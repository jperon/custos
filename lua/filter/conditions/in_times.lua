return function(cfg)
  local in_time_factory = require("filter.conditions.in_time")
  return function(names)
    local window_names = names
    if not (type(names) == "table") then
      window_names = {
        names
      }
    end
    local time_conds = { }
    for _, name in ipairs(window_names) do
      time_conds[#time_conds + 1] = in_time_factory(cfg)(name)
    end
    return {
      capabilities = {
        worker = true,
        nft_static = false,
        nft_dynamic = false
      },
      window_names = window_names,
      eval = function(req)
        for _, time_cond in ipairs(time_conds) do
          local ok, msg = time_cond.eval(req)
          if ok then
            return ok, msg
          end
        end
        return false, "Not in any time window: " .. tostring(table.concat(window_names, ', '))
      end
    }
  end
end
