local os_time = os.time
local os_rename = os.rename
local serialize
serialize = function(sessions)
  local parts = {
    "return {\n"
  }
  for ip, s in pairs(sessions) do
    local safe_ip = ip:gsub('"', '\\"')
    local safe_user = s.user:gsub('"', '\\"')
    parts[#parts + 1] = string.format('  ["%s"] = { user = "%s", expires = %d },\n', safe_ip, safe_user, s.expires)
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
add_session = function(sessions, ip, user, session_ttl)
  sessions[ip] = {
    user = user,
    expires = os_time() + session_ttl
  }
end
local purge_expired
purge_expired = function(sessions)
  local now = os_time()
  for ip, s in pairs(sessions) do
    if now > s.expires then
      sessions[ip] = nil
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
return {
  serialize = serialize,
  write_sessions = write_sessions,
  load_sessions = load_sessions,
  add_session = add_session,
  purge_expired = purge_expired,
  read_cached = read_cached
}
