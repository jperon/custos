local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local VALID_STATES = {
  REACHABLE = true,
  STALE = true,
  DELAY = true,
  PROBE = true,
  PERMANENT = true,
  NOARP = true
}
local parse_neigh_line
parse_neigh_line = function(line)
  local ip, mac, tail = line:match("^(%S+)%s+dev%s+%S+%s+lladdr%s+(%S+)%s+(.+)$")
  if not (ip and mac and tail) then
    return nil
  end
  local state = tail:match("(%S+)%s*$")
  if not (state and VALID_STATES[state]) then
    return nil
  end
  return {
    ip = ip,
    mac = mac
  }
end
local fill_from_neigh
fill_from_neigh = function(mac_clients, ip_to_mac, ts)
  local fh = io.popen("ip neigh show 2>/dev/null")
  if not (fh) then
    return 0
  end
  local count = 0
  for line in fh:lines() do
    local entry = parse_neigh_line(line)
    if entry then
      local mac = entry.mac:lower()
      local ip = entry.ip
      local e = mac_clients[mac] or {
        ips = { }
      }
      e.last_seen = ts
      e.ips[ip] = true
      local family
      if ip:find(":", 1, true) then
        family = "ipv6"
      else
        family = "ipv4"
      end
      e[family] = ip
      mac_clients[mac] = e
      ip_to_mac[ip] = mac
      count = count + 1
    end
  end
  fh:close()
  return count
end
local load
load = function()
  local mac_clients = { }
  local ip_to_mac = { }
  local ts = os.time()
  local n = fill_from_neigh(mac_clients, ip_to_mac, ts)
  log_info({
    action = "neigh_loaded",
    entries = n
  })
  return {
    mac_clients = mac_clients,
    ip_to_mac = ip_to_mac
  }
end
local refresh
refresh = function(mac_clients, ip_to_mac)
  local ts = os.time()
  local n = fill_from_neigh(mac_clients, ip_to_mac, ts)
  log_info({
    action = "neigh_refreshed",
    entries = n
  })
  return n
end
local _mac_clients = nil
local _ip_to_mac = nil
local _last_refresh = 0
local get_mac
get_mac = function(ip)
  if not (_mac_clients) then
    local res = load()
    _mac_clients = res.mac_clients
    _ip_to_mac = res.ip_to_mac
    _last_refresh = os.time()
  end
  if _ip_to_mac[ip] then
    return _ip_to_mac[ip]
  end
  local ts = os.time()
  if ts - _last_refresh > 5 then
    _last_refresh = ts
    refresh(_mac_clients, _ip_to_mac)
    return _ip_to_mac[ip] or "unknown"
  end
  return "unknown"
end
return {
  load = load,
  refresh = refresh,
  get_mac = get_mac,
  parse_neigh_line = parse_neigh_line,
  fill_from_neigh = fill_from_neigh
}
