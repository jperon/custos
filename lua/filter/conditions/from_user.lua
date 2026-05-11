local session_for_mac, enrich_session_ip, bind_session_mac
do
  local _obj_0 = require("auth.sessions")
  session_for_mac, enrich_session_ip, bind_session_mac = _obj_0.session_for_mac, _obj_0.enrich_session_ip, _obj_0.bind_session_mac
end
local config = require("config")
local _get_mac = nil
local _get_mac_tried = false
local safe_get_mac
safe_get_mac = function(ip_str)
  if not (ip_str) then
    return nil
  end
  if not _get_mac_tried then
    _get_mac_tried = true
    local ok, mod = pcall(function()
      return require("mac_learner_ipc")
    end)
    if not (ok) then
      return nil
    end
    _get_mac = mod.get_mac
  end
  if not (_get_mac) then
    return nil
  end
  return _get_mac(ip_str)
end
return function(cfg)
  local sessions_file = (cfg.auth and cfg.auth.sessions_file) or config.auth.sessions_file
  return function(user)
    return function(req)
      local hinted_user = req.user
      if hinted_user and hinted_user ~= "unknown" then
        if user == "_any" then
          return true, "from_user: session active (" .. tostring(hinted_user) .. ")"
        end
        if user == "_none" then
          return false, "from_user: une session est déjà identifiée (" .. tostring(hinted_user) .. ")"
        end
        if hinted_user == user then
          local mac = req.mac
          if not (mac) then
            mac = safe_get_mac(req.src_ip)
          end
          local s = session_for_mac(mac, req.src_ip, sessions_file)
          if s then
            bind_session_mac(s.mac, req.mac, req.src_ip, sessions_file)
            enrich_session_ip(req.mac, req.src_ip, sessions_file)
          end
          return true, "from_user: " .. tostring(req.src_ip) .. " → " .. tostring(hinted_user)
        end
      end
      local mac = req.mac
      if not (mac) then
        mac = safe_get_mac(req.src_ip)
      end
      local s = session_for_mac(mac, req.src_ip, sessions_file)
      if user == "_any" then
        if s then
          bind_session_mac(s.mac, req.mac, req.src_ip, sessions_file)
          enrich_session_ip(req.mac, req.src_ip, sessions_file)
        end
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
      bind_session_mac(s.mac, req.mac, req.src_ip, sessions_file)
      enrich_session_ip(req.mac, req.src_ip, sessions_file)
      return true, "from_user: " .. tostring(req.src_ip) .. " → " .. tostring(s.user)
    end
  end
end
