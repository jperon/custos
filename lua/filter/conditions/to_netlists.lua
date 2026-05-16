return function(cfg)
  local _to_netlist = require("filter.conditions.to_netlist")
  return function(list_names)
    local lists = list_names
    if not (type(list_names) == "table") then
      lists = {
        list_names
      }
    end
    local list_conds = { }
    for _, name in ipairs(lists) do
      list_conds[#list_conds + 1] = _to_netlist(cfg)(name)
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
        return false, tostring(req.dst_ip or '?') .. " not in any netlist"
      end
    }
  end
end
