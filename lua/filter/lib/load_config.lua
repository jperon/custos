local moon_base = require("moonscript.base")
local load_config
load_config = function(path)
  local chunk, load_err = moon_base.loadfile(path)
  if not (chunk) then
    return nil, "impossible de charger " .. tostring(path) .. " : " .. tostring(load_err)
  end
  local ok2, cfg = pcall(chunk)
  if not (ok2) then
    return nil, "erreur à l'exécution de " .. tostring(path) .. " : " .. tostring(cfg)
  end
  if not (type(cfg) == "table") then
    return nil, "configuration vide ou invalide dans " .. tostring(path)
  end
  cfg.nets = cfg.nets or { }
  cfg.macs = cfg.macs or { }
  cfg.times = cfg.times or { }
  cfg.sources = cfg.sources or { }
  cfg.rules = cfg.rules or { }
  cfg.users = cfg.users or { }
  cfg.userlists = cfg.userlists or cfg.users or { }
  cfg.users = cfg.users or cfg.userlists or { }
  cfg.dest_whitelist = cfg.dest_whitelist or { }
  cfg.auth = cfg.auth or { }
  local auth = cfg.auth
  auth.host = auth.host or "::"
  auth.port = auth.port or 33443
  auth.captive_port = auth.captive_port or 33080
  auth.session_ttl = auth.session_ttl or 0
  auth.sessions_file = auth.sessions_file or "/tmp/sessions.lua"
  auth.heartbeat_interval = auth.heartbeat_interval or 30
  auth.idle_timeout = auth.idle_timeout or 120
  auth.secrets = auth.secrets or "/etc/custos/secrets"
  cfg.sni = cfg.sni or { }
  if cfg.sni.enabled == nil then
    cfg.sni.enabled = true
  else
    cfg.sni.enabled = not not cfg.sni.enabled
  end
  cfg.sni.mode = cfg.sni.mode or "strict-443"
  cfg.sni.protocols = cfg.sni.protocols or "both"
  cfg.sni.nft_failure_policy = cfg.sni.nft_failure_policy or "fail-closed"
  return cfg, nil
end
return {
  load_config = load_config
}
