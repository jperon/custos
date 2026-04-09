local ok, lyaml = pcall(require, "lyaml")
if not (ok) then
  error("lyaml introuvable — installer le paquet lua-yaml (apt install lua-yaml)")
end
local load_config
load_config = function(path)
  local fh, err = io.open(path, "r")
  if not (fh) then
    return nil, "impossible d'ouvrir " .. tostring(path) .. " : " .. tostring(err)
  end
  local content = fh:read("*a")
  fh:close()
  local ok2, cfg = pcall(lyaml.load, content)
  if not (ok2) then
    return nil, "erreur de syntaxe YAML dans " .. tostring(path) .. " : " .. tostring(cfg)
  end
  if not (type(cfg) == "table") then
    return nil, "configuration vide ou invalide dans " .. tostring(path)
  end
  cfg.nets = cfg.nets or { }
  cfg.times = cfg.times or { }
  cfg.sources = cfg.sources or { }
  cfg.rules = cfg.rules or { }
  cfg.users = cfg.users or { }
  cfg.auth = cfg.auth or { }
  local auth = cfg.auth
  auth.host = auth.host or "::"
  auth.port = auth.port or 8443
  auth.session_ttl = auth.session_ttl or 86400
  auth.sessions_file = auth.sessions_file or "./tmp/sessions.lua"
  auth.heartbeat_interval = auth.heartbeat_interval or 30
  auth.idle_timeout = auth.idle_timeout or 120
  return cfg, nil
end
return {
  load_config = load_config
}
