local log_debug
log_debug = require("log").log_debug
return function(cfg)
  return function(names)
    local _from_userlist = (require("filter.conditions.from_userlist"))(cfg)
    return function(req)
      local last_reason = nil
      for _, name in ipairs(names) do
        local ok, reason = (_from_userlist(name))(req)
        if ok then
          return true, "In one of: " .. tostring(table.concat(names, ', '))
        end
        last_reason = reason
      end
      if req.user and req.user ~= "unknown" then
        log_debug({
          action = "from_userlists_no_match",
          hinted_user = req.user,
          src_ip = req.src_ip or "",
          lists = table.concat(names, ","),
          last_reason = last_reason or ""
        })
      end
      return false, "Not in any of: " .. tostring(table.concat(names, ', '))
    end
  end
end
