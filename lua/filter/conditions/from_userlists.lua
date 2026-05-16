local log_debug
log_debug = require("log").log_debug
return function(cfg)
  local _from_userlist_factory = require("filter.conditions.from_userlist")
  return function(names)
    local list_names = names
    if not (type(names) == "table") then
      list_names = {
        names
      }
    end
    local list_conds = { }
    for _, name in ipairs(list_names) do
      list_conds[#list_conds + 1] = _from_userlist_factory(cfg)(name)
    end
    return {
      capabilities = {
        worker = true,
        nft = false,
        nft_dynamic = false
      },
      list_names = list_names,
      eval = function(req)
        local last_reason = nil
        for _, list_cond in ipairs(list_conds) do
          local ok, reason = list_cond.eval(req)
          if ok then
            return true, "In one of: " .. tostring(table.concat(list_names, ', '))
          end
          last_reason = reason
        end
        if req.user and req.user ~= "unknown" then
          log_debug({
            action = "from_userlists_no_match",
            hinted_user = req.user,
            src_ip = req.src_ip or "",
            lists = table.concat(list_names, ","),
            last_reason = last_reason or ""
          })
        end
        return false, "Not in any of: " .. tostring(table.concat(list_names, ', '))
      end
    }
  end
end
