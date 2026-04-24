local UCI_PKG = "custos"
local UCI_SEC = "main"
local OUTPUT_DIR = "/var/run/custos"
local DEFAULTS = {
  forced_ttl = 60,
  nft_ip_timeout = "2m",
  ipc_pending_ttl = 5,
  client_expiry = 300,
  neigh_refresh_cooldown = 10,
  nft_add_retry_count = 3,
  nft_add_backoff_ms = "20, 50, 100",
  nft_add_failure_policy = "fail-closed",
  ipc_match_retry_enabled = true,
  ipc_match_retry_count = 5,
  ipc_match_retry_sleep_ms = 20,
  auth_sessions_file = "./tmp/sessions.lua",
  allowed_domains = {
    "local",
    "lan",
    "home.arpa"
  },
  dest_whitelist = { },
  log_level = "INFO"
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
local validate_bool
validate_bool = function(raw, default)
  if not (raw) then
    return default
  end
  if raw == "1" or raw == "true" then
    return true
  end
  if raw == "0" or raw == "false" then
    return false
  end
  return default
end
local validate_ip_cidr
validate_ip_cidr = function(s)
  if not (s and #s > 0) then
    return nil
  end
  s = s:gsub("%s+", "")
  if #s == 0 then
    return nil
  end
  if s:find(":") then
    if s:match("[^%x:%./]") then
      return nil
    end
    if s:match(":::") then
      return nil
    end
  else
    if s:match("[^%d%./]") then
      return nil
    end
    local parts = { }
    for part in s:gmatch("[^/]+") do
      table.insert(parts, part)
    end
    if #parts > 2 then
      return nil
    end
    local ip = parts[1]
    if not (ip) then
      return nil
    end
    local octets = { }
    for octet in ip:gmatch("[^.]+") do
      table.insert(octets, octet)
    end
    if not (#octets == 4) then
      return nil
    end
    for _index_0 = 1, #octets do
      local octet = octets[_index_0]
      local n = tonumber(octet)
      if not (n and n >= 0 and n <= 255) then
        return nil
      end
    end
    if #parts == 2 then
      local mask = tonumber(parts[2])
      if not (mask and mask >= 0 and mask <= 32) then
        return nil
      end
    end
  end
  return s
end
local validate_log_level
validate_log_level = function(raw, default)
  if not (raw) then
    return default
  end
  raw = raw:upper()()
  local valid_levels = {
    ["ERROR"] = true,
    ["WARN"] = true,
    ["INFO"] = true,
    ["DEBUG"] = true,
    ["TRACE"] = true
  }
  if valid_levels[raw] then
    return raw
  end
  io.stderr:write("uci_config: log_level invalide '" .. tostring(raw) .. "', utilise '" .. tostring(default) .. "'\n")
  return default
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
    "local QUEUE_CAPTIVE          = 2",
    "local QUEUE_REJECT           = 3",
    string.format("local FORCED_TTL             = %d", cfg.forced_ttl),
    string.format('local NFT_IP_TIMEOUT         = "%s"', cfg.nft_ip_timeout),
    string.format("local IPC_PENDING_TTL        = %d", cfg.ipc_pending_ttl),
    string.format("local CLIENT_EXPIRY          = %d", cfg.client_expiry),
    string.format("local NEIGH_REFRESH_COOLDOWN = %d", cfg.neigh_refresh_cooldown),
    string.format("local NFT_ADD_RETRY_COUNT    = %d", cfg.nft_add_retry_count),
    string.format("local NFT_ADD_BACKOFF_MS     = { %s }", cfg.nft_add_backoff_ms),
    string.format('local NFT_ADD_FAILURE_POLICY = "%s"', cfg.nft_add_failure_policy),
    string.format("local IPC_MATCH_RETRY_ENABLED = %s", (function()
      if cfg.ipc_match_retry_enabled then
        return "true"
      else
        return "false"
      end
    end)()),
    string.format("local IPC_MATCH_RETRY_COUNT  = %d", cfg.ipc_match_retry_count),
    string.format("local IPC_MATCH_RETRY_SLEEP_MS = %d", cfg.ipc_match_retry_sleep_ms),
    "local NFT_TABLE              = \"dns-filter-bridge\"",
    "local NFT_FAMILY              = \"bridge\"",
    "local NFT_FAMILY6             = \"bridge\"",
    'local NFT_SET_IP4            = "ip4_allowed"',
    'local NFT_SET_IP6            = "ip6_allowed"',
    'local NFT_SET_MAC4           = "mac4_allowed"',
    'local NFT_SET_MAC6           = "mac6_allowed"',
    string.format('local NFT_IP_TIMEOUT         = "%s"', cfg.nft_ip_timeout),
    "local DNS_PORT               = 53",
    "local AF_INET                = 2",
    "local AF_INET6               = 10",
    "local PROTO_UDP              = 17",
    string.format('local AUTH_SESSIONS_FILE     = "%s"', escape_lua_str(cfg.auth_sessions_file)),
    string.format('local LOG_LEVEL              = "%s"', cfg.log_level),
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
  table.insert(lines, "local DEST_WHITELIST = {")
  local _list_1 = cfg.dest_whitelist
  for _index_0 = 1, #_list_1 do
    local ip = _list_1[_index_0]
    table.insert(lines, string.format('  "%s",', escape_lua_str(ip)))
  end
  table.insert(lines, "}")
  table.insert(lines, "")
  table.insert(lines, "local NFT_EXTRA_RULES = {")
  local _list_2 = cfg.nft_extra_rules
  for _index_0 = 1, #_list_2 do
    local r = _list_2[_index_0]
    table.insert(lines, string.format('  "%s",', escape_lua_str(r)))
  end
  table.insert(lines, "}")
  table.insert(lines, "")
  table.insert(lines, "return {")
  local _list_3 = {
    "QUEUE_QUESTIONS",
    "QUEUE_RESPONSES",
    "QUEUE_CAPTIVE",
    "QUEUE_REJECT",
    "ALLOWED_DOMAINS",
    "DEST_WHITELIST",
    "NFT_TABLE",
    "NFT_FAMILY",
    "NFT_FAMILY6",
    "NFT_SET_IP4",
    "NFT_SET_IP6",
    "NFT_SET_MAC4",
    "NFT_SET_MAC6",
    "NFT_IP_TIMEOUT",
    "NFT_EXTRA_RULES",
    "IPC_PENDING_TTL",
    "CLIENT_EXPIRY",
    "NEIGH_REFRESH_COOLDOWN",
    "FORCED_TTL",
    "DNS_PORT",
    "AF_INET",
    "AF_INET6",
    "PROTO_UDP",
    "AUTH_SESSIONS_FILE",
    "NFT_ADD_RETRY_COUNT",
    "NFT_ADD_BACKOFF_MS",
    "NFT_ADD_FAILURE_POLICY",
    "IPC_MATCH_RETRY_ENABLED",
    "IPC_MATCH_RETRY_COUNT",
    "IPC_MATCH_RETRY_SLEEP_MS",
    "LOG_LEVEL"
  }
  for _index_0 = 1, #_list_3 do
    local k = _list_3[_index_0]
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
  local raw_whitelist = uci_get_list("dest_whitelist")
  local whitelist = { }
  for _index_0 = 1, #raw_whitelist do
    local ip = raw_whitelist[_index_0]
    local valid = validate_ip_cidr(ip)
    if valid then
      table.insert(whitelist, valid)
    end
  end
  if #whitelist == 0 then
    whitelist = DEFAULTS.dest_whitelist
  end
  local cfg = {
    forced_ttl = validate_posint(uci_get("forced_ttl"), DEFAULTS.forced_ttl),
    nft_ip_timeout = validate_nft_timeout(uci_get("nft_ip_timeout"), DEFAULTS.nft_ip_timeout),
    ipc_pending_ttl = validate_posint(uci_get("ipc_pending_ttl"), DEFAULTS.ipc_pending_ttl),
    client_expiry = validate_posint(uci_get("client_expiry"), DEFAULTS.client_expiry),
    neigh_refresh_cooldown = validate_posint(uci_get("neigh_refresh_cooldown"), DEFAULTS.neigh_refresh_cooldown),
    nft_add_retry_count = validate_posint(uci_get("nft_add_retry_count"), DEFAULTS.nft_add_retry_count),
    nft_add_backoff_ms = uci_get("nft_add_backoff_ms") or DEFAULTS.nft_add_backoff_ms,
    nft_add_failure_policy = uci_get("nft_add_failure_policy") or DEFAULTS.nft_add_failure_policy,
    ipc_match_retry_enabled = validate_bool(uci_get("ipc_match_retry_enabled"), DEFAULTS.ipc_match_retry_enabled),
    ipc_match_retry_count = validate_posint(uci_get("ipc_match_retry_count"), DEFAULTS.ipc_match_retry_count),
    ipc_match_retry_sleep_ms = validate_posint(uci_get("ipc_match_retry_sleep_ms"), DEFAULTS.ipc_match_retry_sleep_ms),
    auth_sessions_file = uci_get("auth_sessions_file") or DEFAULTS.auth_sessions_file,
    allowed_domains = domains,
    dest_whitelist = whitelist,
    nft_extra_rules = uci_get_list("nft_extra_rules"),
    log_level = validate_log_level(uci_get("log_level"), DEFAULTS.log_level)
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
