return function(cfg)
  local _from_user_factory = require("filter.conditions.from_user")
  return function(users)
    local user_list = users
    if not (type(users) == "table") then
      user_list = {
        users
      }
    end
    local user_conds = { }
    for _, user in ipairs(user_list) do
      user_conds[#user_conds + 1] = _from_user_factory(cfg)(user)
    end
    return {
      capabilities = {
        worker = true,
        nft = false,
        nft_dynamic = false
      },
      user_list = user_list,
      eval = function(req)
        for _, user_cond in ipairs(user_conds) do
          local ok, msg = user_cond.eval(req)
          if ok then
            return ok, msg
          end
        end
        return false, "Not matched by any user"
      end
    }
  end
end
