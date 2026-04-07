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
  local ip, mac, state = line:match("^(%S+)%s+dev%s+%S+%s+lladdr%s+(%S+)%s+(%S+)")
  if not (ip and mac and state) then
    return nil
  end
  if not (VALID_STATES[state]) then
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
      local mac = entry.mac
      local ip = entry.ip
      local family
      if ip:find(":", 1, true) then
        family = "ipv6"
      else
        family = "ipv4"
      end
      local e = mac_clients[mac] or { }
      e.last_seen = ts
      local old_ip = e[family]
      if old_ip ~= ip then
        if old_ip then
          ip_to_mac[old_ip] = nil
        end
        e[family] = ip
        ip_to_mac[ip] = mac
      end
      mac_clients[mac] = e
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
return {
  load = load,
  refresh = refresh,
  parse_neigh_line = parse_neigh_line,
  fill_from_neigh = fill_from_neigh
}
