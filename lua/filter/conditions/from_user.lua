local session_for_ip
session_for_ip = require("auth.sessions").session_for_ip
local AUTH_SESSIONS_FILE
AUTH_SESSIONS_FILE = require("config").AUTH_SESSIONS_FILE
return function(cfg)
  local sessions_file = (cfg.auth and cfg.auth.sessions_file) or AUTH_SESSIONS_FILE
  return function(user)
    return function(req)
      local s = session_for_ip(req.src_ip, sessions_file, req.mac)
      if not (s) then
        return false, "from_user: aucune session valide pour " .. tostring(req.src_ip)
      end
      if s.user ~= user then
        return false, "from_user: " .. tostring(req.src_ip) .. " authentifié en tant que " .. tostring(s.user) .. ", attendu " .. tostring(user)
      end
      return true, "from_user: " .. tostring(req.src_ip) .. " → " .. tostring(s.user)
    end
  end
end
