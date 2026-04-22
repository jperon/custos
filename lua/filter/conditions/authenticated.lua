local session_for_mac
session_for_mac = require("auth.sessions").session_for_mac
local AUTH_SESSIONS_FILE
AUTH_SESSIONS_FILE = require("config").AUTH_SESSIONS_FILE
return function(cfg)
  local sessions_file = (cfg.auth and cfg.auth.sessions_file) or AUTH_SESSIONS_FILE
  return function(required)
    return function(req)
      local s = session_for_mac(req.mac, req.src_ip, sessions_file)
      if s == required then
        return true, "authenticated: " .. tostring(req.src_ip) .. " → " .. tostring(s.user)
      end
      return false, "authenticated: aucune session valide pour " .. tostring(req.src_ip)
    end
  end
end
