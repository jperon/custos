local get_session
get_session = require("auth.user_sessions").get_session
return function(cfg)
  return function(username)
    return function(req)
      if not (username) then
        return false, "from_authenticated_user: no username specified"
      end
      local session = get_session(username)
      if not (session) then
        return false, "from_authenticated_user: user " .. tostring(username) .. " not authenticated"
      end
      if req.src_ip and session.src_ip ~= req.src_ip then
        return false, "from_authenticated_user: IP mismatch for " .. tostring(username)
      end
      if req.mac and session.mac ~= req.mac:lower() then
        return false, "from_authenticated_user: MAC mismatch for " .. tostring(username)
      end
      return true, "from_authenticated_user: user " .. tostring(username) .. " authenticated"
    end
  end
end
