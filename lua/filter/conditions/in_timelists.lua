return function(cfg)
  local in_timelist_factory = require("filter.conditions.in_timelist")
  return function(list_names)
    local lists = list_names
    if not (type(list_names) == "table") then
      lists = {
        list_names
      }
    end
    local list_conds = { }
    for _, name in ipairs(lists) do
      list_conds[#list_conds + 1] = in_timelist_factory(cfg)(name)
    end
    return {
      capabilities = {
        worker = true,
        nft = false,
        nft_dynamic = false
      },
      lists = lists,
      eval = function(req)
        for _, list_cond in ipairs(list_conds) do
          local ok, reason = list_cond.eval(req)
          if ok then
            return true, reason
          end
        end
        return false, "Outside all windows in specified lists"
      end
    }
  end
end
