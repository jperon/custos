return function(cfg)
  local to_domainlist_factory = require("filter.conditions.to_domainlist")
  return function(listnames)
    local lists = listnames
    if not (type(listnames) == "table") then
      lists = {
        listnames
      }
    end
    local list_conds = { }
    for _, name in ipairs(lists) do
      list_conds[#list_conds + 1] = to_domainlist_factory(cfg)(name)
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
        return false, "Domain not in any of: " .. tostring(table.concat(lists, ', '))
      end,
      creates_dynamic_scope = true
    }
  end
end
