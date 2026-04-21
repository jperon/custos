local session_for_ip
session_for_ip = require("auth.sessions").session_for_ip
local AUTH_SESSIONS_FILE
AUTH_SESSIONS_FILE = require("config").AUTH_SESSIONS_FILE
return function(cfg)
  local sessions_file = (cfg.auth and cfg.auth.sessions_file) or AUTH_SESSIONS_FILE
  return function(rule)
    return function(req)
      local s = session_for_ip(req.src_ip, sessions_file, req.mac)
      if s then
        return true, "allow (auth=" .. tostring(s.user) .. ") by rule: " .. tostring(rule.description or '?')
      end
      return "dnsonly", "DNS only (no nft) by rule: " .. tostring(rule.description or '?')
    end
  end
end
