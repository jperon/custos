local log_debug
log_debug = require("log").log_debug
return function(cfg)
  local _from_user_factory = require("filter.conditions.from_user")
  return function(name)
    local userlists_cfg = cfg.userlists or { }
    local sessions_file = (cfg.auth and cfg.auth.sessions_file) or "unknown"
    local userlist = userlists_cfg[name]
    if not (userlist) then
      return {
        capabilities = {
          worker = true,
          nft_static = false,
          nft_dynamic = false
        },
        eval = function(req)
          if req.user and req.user ~= "unknown" then
            log_debug({
              action = "from_userlist_missing",
              list = name,
              hinted_user = req.user,
              src_ip = req.src_ip or "",
              sessions_file = sessions_file
            })
          end
          return false, "User list '" .. tostring(name) .. "' not defined"
        end
      }
    end
    local user_conds = { }
    for _index_0 = 1, #userlist do
      local user = userlist[_index_0]
      user_conds[#user_conds + 1] = _from_user_factory(cfg)(user)
    end
    return {
      capabilities = {
        worker = true,
        nft_static = false,
        nft_dynamic = false
      },
      name = name,
      userlist = userlist,
      eval = function(req)
        local last_reason = nil
        for _, user_cond in ipairs(user_conds) do
          local ok, reason = user_cond.eval(req)
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
    }
  end
end
