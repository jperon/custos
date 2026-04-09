local read_cached
read_cached = require("auth.sessions").read_cached
local AUTH_SESSIONS_FILE
AUTH_SESSIONS_FILE = require("config").AUTH_SESSIONS_FILE
return function(cfg)
  local sessions_file = (cfg.auth and cfg.auth.sessions_file) or AUTH_SESSIONS_FILE
  return function(user)
    return function(req)
      local sessions = read_cached(sessions_file)
      local s = sessions[req.src_ip]
      local now = os.time()
      if not s then
        return false, "from_user: aucune session pour " .. tostring(req.src_ip)
      end
      if now > s.expires then
        return false, "from_user: session expirée pour " .. tostring(req.src_ip) .. " (user=" .. tostring(s.user) .. ")"
      end
      if s.user ~= user then
        return false, "from_user: " .. tostring(req.src_ip) .. " authentifié en tant que " .. tostring(s.user) .. ", attendu " .. tostring(user)
      end
      return true, "from_user: " .. tostring(req.src_ip) .. " → " .. tostring(s.user)
    end
  end
end
