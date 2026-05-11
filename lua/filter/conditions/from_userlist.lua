local log_debug
log_debug = require("log").log_debug
return function(cfg)
  return function(name)
    local _from_user = (require("filter.conditions.from_user"))(cfg)
    local userlists_cfg = cfg.userlists or { }
    local sessions_file = (cfg.auth and cfg.auth.sessions_file) or "unknown"
    return function(req)
      local userlist = userlists_cfg[name]
      if not userlist and req.user and req.user ~= "unknown" then
        log_debug({
          action = "from_userlist_missing",
          list = name,
          hinted_user = req.user,
          src_ip = req.src_ip or "",
          sessions_file = sessions_file
        })
      end
      if not (userlist) then
        return false, "User list '" .. tostring(name) .. "' not defined"
      end
      local last_reason = nil
      for _index_0 = 1, #userlist do
        local user = userlist[_index_0]
        local ok, reason = (_from_user(user))(req)
        if ok then
          return true, tostring(req.src_ip) .. " in userlist '" .. tostring(name) .. "'"
        end
        last_reason = reason
      end
      if req.user and req.user ~= "unknown" then
        log_debug({
          action = "from_userlist_no_match",
          list = name,
          hinted_user = req.user,
          src_ip = req.src_ip or "",
          list_size = #userlist,
          sessions_file = sessions_file,
          last_reason = last_reason or ""
        })
      end
      return false, "Not in userlist '" .. tostring(name) .. "'"
    end
  end
end
