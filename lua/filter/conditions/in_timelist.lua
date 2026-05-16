return function(cfg)
  local in_time_factory = require("filter.conditions.in_time")
  return function(list_name)
    local time_lists = cfg.times_lists or { }
    local window_names = time_lists[list_name]
    if not (window_names) then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "Time list '" .. tostring(list_name) .. "' not defined"
        end
      }
    end
    local window_conds = { }
    for _, name in ipairs(window_names) do
      window_conds[#window_conds + 1] = in_time_factory(cfg)(name)
    end
    return {
      capabilities = {
        worker = true,
        nft = false,
        nft_dynamic = false
      },
      list_name = list_name,
      window_names = window_names,
      eval = function(req)
        for _, window_cond in ipairs(window_conds) do
          local ok, reason = window_cond.eval(req)
          if ok then
            return true, reason
          end
        end
        return false, "Outside all windows in list '" .. tostring(list_name) .. "'"
      end
    }
  end
end
