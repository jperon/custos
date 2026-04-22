local session_for_mac
session_for_mac = require("auth.sessions").session_for_mac
local AUTH_SESSIONS_FILE
AUTH_SESSIONS_FILE = require("config").AUTH_SESSIONS_FILE
return function(cfg)
  local sessions_file = (cfg.auth and cfg.auth.sessions_file) or AUTH_SESSIONS_FILE
  return function(user)
    return function(req)
      local s = session_for_mac(req.mac, req.src_ip, sessions_file)
      if user == "_any" then
        return s ~= nil, "from_user: session active (" .. tostring(s and s.user or 'unknown') .. ")"
      end
      if user == "_none" then
        return s == nil, "from_user: aucune session active"
      end
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
