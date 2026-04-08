local UCI_PKG = "custos"
local UCI_SEC = "main"
local OUTPUT_DIR = "/var/run/custos"
local DEFAULTS = {
  log_path = "/var/log/custos.log",
  forced_ttl = 60,
  nft_ip_timeout = "2m",
  ipc_pending_ttl = 5,
  client_expiry = 300,
  neigh_refresh_cooldown = 10,
  allowed_domains = {
    "local",
    "lan",
    "home.arpa"
  }
}
local uci_get
uci_get = function(option)
  local fh = io.popen("uci get " .. tostring(UCI_PKG) .. "." .. tostring(UCI_SEC) .. "." .. tostring(option) .. " 2>/dev/null")
  if not (fh) then
    return nil
  end
  local val = fh:read("*l")
  fh:close()
  if val and val ~= "" then
    return val
  end
end
local uci_get_list
uci_get_list = function(option)
  local fh = io.popen("uci show " .. tostring(UCI_PKG) .. "." .. tostring(UCI_SEC) .. "." .. tostring(option) .. " 2>/dev/null")
  if not (fh) then
    return { }
  end
  local content = fh:read("*a")
  fh:close()
  local result = { }
  for val in content:gmatch("'([^']*)'") do
    table.insert(result, val)
  end
  return result
end
local validate_posint
validate_posint = function(raw, default)
  if not (raw) then
    return default
  end
  local n = tonumber(raw)
  if not (n and math.floor(n) == n and n > 0) then
    return default
  end
  return n
end
local validate_nft_timeout
validate_nft_timeout = function(raw, default)
  if not (raw) then
    return default
  end
  if raw:match("^%d+%a+$") then
    return raw
  end
  io.stderr:write("uci_config: nft_ip_timeout invalide '" .. tostring(raw) .. "', utilise '" .. tostring(default) .. "'\n")
  return default
end
local validate_path
validate_path = function(raw, default)
  if not (raw) then
    return default
  end
  if raw:match("[;`$|<>&!]" or raw:match("%.%.")) then
    io.stderr:write("uci_config: log_path suspect '" .. tostring(raw) .. "', utilise '" .. tostring(default) .. "'\n")
    return default
  end
  return raw
end
local validate_domain
validate_domain = function(d)
  if not (d and #d > 0 and #d <= 253) then
    return nil
  end
  if d:match("[^%a%d%.%-]") then
    return nil
  end
  return d
end
local escape_lua_str
escape_lua_str = function(s)
  return s:gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n")
end
local generate_config
generate_config = function(cfg)
  local lines = {
    "-- config.lua — généré par uci_config.lua depuis /etc/config/custos",
    "-- Ne pas modifier : écrasé au démarrage/rechargement du service.",
    "",
    "local QUEUE_QUESTIONS        = 0",
    "local QUEUE_RESPONSES        = 1",
    'local DOCKER_MODE            = os.getenv("DOCKER_MODE") == "1"',
    string.format('local LOG_PATH               = "%s"', escape_lua_str(cfg.log_path)),
    string.format("local FORCED_TTL             = %d", cfg.forced_ttl),
    string.format('local NFT_IP_TIMEOUT         = "%s"', cfg.nft_ip_timeout),
    string.format("local IPC_PENDING_TTL        = %d", cfg.ipc_pending_ttl),
    string.format("local CLIENT_EXPIRY          = %d", cfg.client_expiry),
    string.format("local NEIGH_REFRESH_COOLDOWN = %d", cfg.neigh_refresh_cooldown),
    'local NFT_TABLE              = "dns-filter"',
    'local NFT_SET_IP4            = "ip4_allowed"',
    'local NFT_SET_IP6            = "ip6_allowed"',
    "local IPC_MSG_SIZE           = 27",
    "local DNS_PORT               = 53",
    "local AF_INET                = 2",
    "local AF_INET6               = 10",
    "local PROTO_UDP              = 17",
    "",
    "local ALLOWED_DOMAINS = {"
  }
  local _list_0 = cfg.allowed_domains
  for _index_0 = 1, #_list_0 do
    local d = _list_0[_index_0]
    table.insert(lines, string.format('  "%s",', escape_lua_str(d)))
  end
  table.insert(lines, "}")
  table.insert(lines, "")
  table.insert(lines, "return {")
  local _list_1 = {
    "QUEUE_QUESTIONS",
    "QUEUE_RESPONSES",
    "DOCKER_MODE",
    "LOG_PATH",
    "ALLOWED_DOMAINS",
    "NFT_TABLE",
    "NFT_SET_IP4",
    "NFT_SET_IP6",
    "NFT_IP_TIMEOUT",
    "IPC_MSG_SIZE",
    "IPC_PENDING_TTL",
    "CLIENT_EXPIRY",
    "NEIGH_REFRESH_COOLDOWN",
    "FORCED_TTL",
    "DNS_PORT",
    "AF_INET",
    "AF_INET6",
    "PROTO_UDP"
  }
  for _index_0 = 1, #_list_1 do
    local k = _list_1[_index_0]
    table.insert(lines, string.format("  %-24s = %s,", k, k))
  end
  table.insert(lines, "}")
  return table.concat(lines, "\n")
end
local main
main = function()
  local raw_domains = uci_get_list("allowed_domains")
  local domains = { }
  for _index_0 = 1, #raw_domains do
    local d = raw_domains[_index_0]
    local valid = validate_domain(d)
    if valid then
      table.insert(domains, valid)
    end
  end
  if #domains == 0 then
    domains = DEFAULTS.allowed_domains
  end
  local cfg = {
    log_path = validate_path(uci_get("log_path"), DEFAULTS.log_path),
    forced_ttl = validate_posint(uci_get("forced_ttl"), DEFAULTS.forced_ttl),
    nft_ip_timeout = validate_nft_timeout(uci_get("nft_ip_timeout"), DEFAULTS.nft_ip_timeout),
    ipc_pending_ttl = validate_posint(uci_get("ipc_pending_ttl"), DEFAULTS.ipc_pending_ttl),
    client_expiry = validate_posint(uci_get("client_expiry"), DEFAULTS.client_expiry),
    neigh_refresh_cooldown = validate_posint(uci_get("neigh_refresh_cooldown"), DEFAULTS.neigh_refresh_cooldown),
    allowed_domains = domains
  }
  if os.execute("mkdir -p " .. tostring(OUTPUT_DIR)) ~= 0 then
    io.stderr:write("uci_config: impossible de créer " .. tostring(OUTPUT_DIR) .. "\n")
    os.exit(1)
  end
  local tmp_path = tostring(OUTPUT_DIR) .. "/config.lua.tmp"
  local output_path = tostring(OUTPUT_DIR) .. "/config.lua"
  local fh, err = io.open(tmp_path, "w")
  if not (fh) then
    io.stderr:write("uci_config: écriture impossible " .. tostring(tmp_path) .. ": " .. tostring(err) .. "\n")
    os.exit(1)
  end
  fh:write(generate_config(cfg))
  fh:close()
  local ok, mv_err = os.rename(tmp_path, output_path)
  if not (ok) then
    io.stderr:write("uci_config: rename échoué: " .. tostring(mv_err) .. "\n")
    os.execute("rm -f " .. tostring(tmp_path))
    os.exit(1)
  end
  return io.write("uci_config: " .. tostring(output_path) .. " écrit\n")
end
return main()
