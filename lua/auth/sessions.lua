local os_time = os.time
local os_rename = os.rename
local log_info
log_info = require("log").log_info
local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local AT_FDCWD = -100
local AT_STATX_SYNC_AS_STAT = 0x0000
local STATX_BASIC_STATS = 0x000007ff
local _statx_buf = ffi.new("struct statx[1]")
local file_sig
file_sig = function(path)
  if not (path) then
    return nil
  end
  local ok, rv = pcall(libc.statx, AT_FDCWD, path, AT_STATX_SYNC_AS_STAT, STATX_BASIC_STATS, _statx_buf)
  if not (ok and rv == 0) then
    return nil
  end
  local s = _statx_buf[0]
  local m = s.stx_mtime
  return string.format("%d.%09d:%d:%d", tonumber(m.tv_sec), tonumber(m.tv_nsec), tonumber(s.stx_size), tonumber(s.stx_ino))
end
local serialize
serialize = function(sessions)
  local parts = {
    "return {\n"
  }
  for mac, s in pairs(sessions) do
    local safe_mac = mac:gsub('"', '\\"')
    local safe_user = s.user:gsub('"', '\\"')
    local expires_str = s.expires and (", expires = " .. tostring(s.expires)) or ""
    local ips_parts = { }
    if s.ips then
      for family, ip in pairs(s.ips) do
        ips_parts[#ips_parts + 1] = string.format('%s = "%s"', family, ip:gsub('"', '\\"'))
      end
    end
    local ips_str = #ips_parts > 0 and (", ips = { " .. table.concat(ips_parts, ", ") .. " }") or ""
    parts[#parts + 1] = string.format('  ["%s"] = { user = "%s"%s%s, mac = "%s" },\n', safe_mac, safe_user, expires_str, ips_str, safe_mac)
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
add_session = function(sessions, mac, ip, user, expires)
  if not (mac and mac ~= "unknown") then
    return 
  end
  mac = mac:lower()
  local s = sessions[mac] or {
    ips = { }
  }
  s.mac = mac
  s.user = user
  s.expires = expires
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
    if s.expires and now > s.expires then
      sessions[mac] = nil
    end
  end
end
local _cache = nil
local _cache_time = 0
local _cache_sig = nil
local CACHE_TTL = 5
local read_cached
read_cached = function(path)
  local now = os_time()
  if not _cache or (now - _cache_time) >= CACHE_TTL then
    _cache = load_sessions(path)
    _cache_time = now
    _cache_sig = file_sig(path)
  end
  return _cache
end
local reload_cached
reload_cached = function(path)
  _cache = load_sessions(path)
  _cache_time = os_time()
  _cache_sig = file_sig(path)
  return _cache
end
local reset_cache
reset_cache = function()
  _cache = nil
  _cache_time = 0
  _cache_sig = nil
end
local reload_needed
reload_needed = function(path)
  local cur = file_sig(path)
  if not (cur and _cache_sig) then
    return true
  end
  return cur ~= _cache_sig
end
local valid_mac
valid_mac = function(mac)
  return mac and mac ~= "unknown" and mac ~= "\x00\x00\x00\x00\x00\x00"
end
local find_session_by_ip
find_session_by_ip = function(sessions, ip)
  if not (ip) then
    return nil, nil
  end
  for m, sess in pairs(sessions) do
    if sess.ips and (sess.ips.ipv4 == ip or sess.ips.ipv6 == ip) then
      return m, sess
    end
  end
  return nil, nil
end
local enrich_session_ip
enrich_session_ip = function(mac, ip, path)
  if not (valid_mac(mac) and ip and path) then
    return false
  end
  mac = mac:lower()
  local sessions = load_sessions(path)
  local s = sessions[mac]
  if not (s) then
    local _old_mac, found = find_session_by_ip(sessions, ip)
    s = found
  end
  if not (s) then
    return false
  end
  local family
  if ip:find(":", 1, true) then
    family = "ipv6"
  else
    family = "ipv4"
  end
  s.ips = s.ips or { }
  if s.ips[family] and s.ips[family] ~= ip then
    return false
  end
  if s.ips[family] == ip and sessions[mac] == s then
    return false
  end
  s.ips[family] = ip
  s.mac = mac
  sessions[mac] = s
  write_sessions(sessions, path)
  reset_cache()
  return true
end
local bind_session_mac
bind_session_mac = function(session_mac, current_mac, ip, path)
  if not (valid_mac(current_mac) and path) then
    return false
  end
  current_mac = current_mac:lower()
  session_mac = session_mac and session_mac:lower() or nil
  if session_mac == current_mac then
    return enrich_session_ip(current_mac, ip, path)
  end
  local sessions = load_sessions(path)
  local s = (session_mac and sessions[session_mac]) or nil
  if not (s) then
    local _old_mac, found = find_session_by_ip(sessions, ip)
    session_mac = _old_mac
    s = found
  end
  if not (s) then
    return false
  end
  s.mac = current_mac
  if ip then
    local family
    if ip:find(":", 1, true) then
      family = "ipv6"
    else
      family = "ipv4"
    end
    s.ips = s.ips or { }
    local _update_0 = family
    s.ips[_update_0] = s.ips[_update_0] or ip
  end
  sessions[current_mac] = s
  if session_mac and session_mac ~= current_mac then
    sessions[session_mac] = nil
  end
  write_sessions(sessions, path)
  reset_cache()
  return true
end
local lookup_session
lookup_session = function(sessions_table, lookup_mac, ip)
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
  return s
end
local session_for_mac
session_for_mac = function(mac, ip, path, sessions_arg)
  local sessions_table = sessions_arg or read_cached(path)
  if not (sessions_table) then
    return nil
  end
  local lookup_mac = mac
  lookup_mac = (lookup_mac and lookup_mac ~= "unknown") and lookup_mac:lower() or "unknown"
  local s = lookup_session(sessions_table, lookup_mac, ip)
  if not s and not sessions_arg and path and reload_needed(path) then
    sessions_table = reload_cached(path)
    if sessions_table then
      s = lookup_session(sessions_table, lookup_mac, ip)
    end
  end
  if not (s) then
    return nil
  end
  local now = os_time()
  if s.expires and now > s.expires then
    if not sessions_arg and path and reload_needed(path) then
      sessions_table = reload_cached(path)
      if sessions_table then
        s = lookup_session(sessions_table, lookup_mac, ip)
      end
      if not (s) then
        return nil
      end
      now = os_time()
    end
    if s.expires and now > s.expires then
      return nil
    end
  end
  if ip then
    local family
    if ip:find(":", 1, true) then
      family = "ipv6"
    else
      family = "ipv4"
    end
    s.ips = s.ips or { }
    local _update_0 = family
    s.ips[_update_0] = s.ips[_update_0] or ip
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
  enrich_session_ip = enrich_session_ip,
  bind_session_mac = bind_session_mac
}
