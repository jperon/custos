local os_time = os.time
local os_rename = os.rename
local log_info
log_info = require("log").log_info
local serialize
serialize = function(sessions)
  local parts = {
    "return {\n"
  }
  for mac, s in pairs(sessions) do
    local safe_mac = mac:gsub('"', '\\"')
    local safe_user = s.user:gsub('"', '\\"')
    local expires = s.expires and (", expires = " .. tostring(s.expires)) or ""
    local hb = s.heartbeat and (", heartbeat = " .. tostring(s.heartbeat)) or ""
    local ca = s.created_at and (", created_at = " .. tostring(s.created_at)) or ""
    local ips_parts = { }
    if s.ips then
      for family, ip in pairs(s.ips) do
        ips_parts[#ips_parts + 1] = string.format('%s = "%s"', family, ip:gsub('"', '\\"'))
      end
    end
    local ips_str = #ips_parts > 0 and (", ips = { " .. table.concat(ips_parts, ", ") .. " }") or ""
    parts[#parts + 1] = string.format('  ["%s"] = { user = "%s"%s%s%s%s, mac = "%s" },\n', safe_mac, safe_user, expires, hb, ca, ips_str, safe_mac)
  end
  parts[#parts + 1] = "}\n"
  return table.concat(parts)
end
local write_sessions
write_sessions = function(sessions, path)
  local tmp_path = path .. ".new"
  local fh, err = io.open(tmp_path, "w")
  if not (fh) then
    return false, "impossible d'écrire " .. tostring(tmp_path) .. " : " .. tostring(err)
  end
  fh:write(serialize(sessions))
  fh:close()
  local ok, err2 = os_rename(tmp_path, path)
  if not (ok) then
    return false, "rename() échoué : " .. tostring(tostring(err2))
  end
  return true
end
local load_sessions
load_sessions = function(path)
  if not (path) then
    return { }
  end
  local fn, _err = loadfile(path)
  if not (fn) then
    return { }
  end
  local ok, result = pcall(fn)
  if not (ok and type(result) == "table") then
    return { }
  end
  return result
end
local add_session
add_session = function(sessions, mac, ip, user, session_ttl, idle_timeout)
  if not (mac and mac ~= "unknown") then
    return 
  end
  mac = mac:lower()
  local now = os_time()
  local hb = (idle_timeout and idle_timeout > 0) and (now + idle_timeout) or nil
  local s = sessions[mac] or {
    ips = { }
  }
  s.mac = mac
  s.user = user
  if session_ttl and session_ttl > 0 then
    s.expires = now + session_ttl
  else
    s.expires = nil
  end
  s.heartbeat = hb
  s.created_at = s.created_at or now
  if ip then
    local family
    if ip:find(":", 1, true) then
      family = "ipv6"
    else
      family = "ipv4"
    end
    s.ips[family] = ip
  end
  sessions[mac] = s
end
local purge_expired
purge_expired = function(sessions)
  local now = os_time()
  for mac, s in pairs(sessions) do
    if (s.expires and now > s.expires) or (s.heartbeat and now > s.heartbeat) then
      sessions[mac] = nil
    end
  end
end
local _cache = nil
local _cache_time = 0
local CACHE_TTL = 5
local read_cached
read_cached = function(path)
  local now = os_time()
  if not _cache or (now - _cache_time) >= CACHE_TTL then
    _cache = load_sessions(path)
    _cache_time = now
  end
  return _cache
end
local reset_cache
reset_cache = function()
  _cache = nil
  _cache_time = 0
end
local session_for_mac
session_for_mac = function(mac, ip, path, sessions_arg)
  local sessions_table = sessions_arg or read_cached(path)
  if not (sessions_table) then
    return nil
  end
  local lookup_mac = mac
  lookup_mac = (lookup_mac and lookup_mac ~= "unknown") and lookup_mac:lower() or "unknown"
  local s = sessions_table[lookup_mac]
  if not s and ip then
    for m, sess in pairs(sessions_table) do
      if sess.ips then
        if sess.ips.ipv4 == ip or sess.ips.ipv6 == ip then
          s = sess
          s.mac = m
          break
        end
      end
    end
  end
  if not (s) then
    return nil
  end
  if ip then
    local family
    if ip:find(":", 1, true) then
      family = "ipv6"
    else
      family = "ipv4"
    end
    s.ips = s.ips or { }
    s.ips[family] = ip
  end
  local now = os_time()
  if s.expires and now > s.expires then
    return nil
  end
  if s.heartbeat and now > s.heartbeat then
    return nil
  end
  return s
end
local user_for_mac
user_for_mac = function(mac, ip, path)
  local s = session_for_mac(mac, ip, path)
  return s and s.user
end
return {
  serialize = serialize,
  write_sessions = write_sessions,
  load_sessions = load_sessions,
  add_session = add_session,
  purge_expired = purge_expired,
  read_cached = read_cached,
  reset_cache = reset_cache,
  session_for_mac = session_for_mac,
  user_for_mac = user_for_mac,
  session_for_ip = function(ip, path, mac)
    return session_for_mac(mac, ip, path)
  end,
  user_for_ip = function(ip, path, mac)
    return user_for_mac(mac, ip, path)
  end
}
