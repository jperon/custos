return function(cfg)
  local _from_maclist = require("filter.conditions.from_maclist")
  return function(list_names)
    local lists = list_names
    if not (type(list_names) == "table") then
      lists = {
        list_names
      }
    end
    local list_conds = { }
    for _, name in ipairs(lists) do
      list_conds[#list_conds + 1] = _from_maclist(cfg)(name)
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
          local ok, msg = list_cond.eval(req)
          if ok then
            return ok, msg
          end
        end
        return false, "mac " .. tostring(req.mac or '?') .. " not in any list"
      end
    }
  end
end
