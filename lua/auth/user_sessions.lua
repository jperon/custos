local log_info, log_warn, log_debug
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug
end
local _sessions = { }
local _session_timeout = 3600
local init
init = function(timeout)
  _session_timeout = timeout or 3600
  _sessions = { }
end
local add_session
add_session = function(username, src_ip, mac)
  if not (username and src_ip and mac) then
    return false
  end
  local username_lower = username:lower()
  local now = os.time()
  _sessions[username_lower] = {
    username = username_lower,
    src_ip = src_ip,
    mac = mac:lower(),
    auth_time = now,
    expires = now + _session_timeout
  }
  if log_debug then
    log_debug(function()
      return {
        action = "user_session_added",
        username = username_lower,
        src_ip = src_ip,
        mac = mac,
        expires_in_s = _session_timeout
      }
    end)
  end
  return true
end
local get_session
get_session = function(username)
  if not (username) then
    return nil
  end
  local username_lower = username:lower()
  local session = _sessions[username_lower]
  if not (session) then
    return nil
  end
  local now = os.time()
  if session.expires and now > session.expires then
    _sessions[username_lower] = nil
    if log_debug then
      log_debug(function()
        return {
          action = "user_session_expired",
          username = username_lower
        }
      end)
    end
    return nil
  end
  return session
end
local is_authenticated
is_authenticated = function(username, src_ip, mac)
  local session = get_session(username)
  if not (session) then
    return false
  end
  if src_ip and session.src_ip ~= src_ip then
    return false
  end
  if mac and session.mac ~= mac:lower() then
    return false
  end
  return true
end
local refresh_session
refresh_session = function(username)
  local session = get_session(username)
  if not (session) then
    return false
  end
  local now = os.time()
  session.expires = now + _session_timeout
  if log_debug then
    log_debug(function()
      return {
        action = "user_session_refreshed",
        username = username:lower(),
        expires_in_s = _session_timeout
      }
    end)
  end
  return true
end
local remove_session
remove_session = function(username)
  if not (username) then
    return false
  end
  local username_lower = username:lower()
  if _sessions[username_lower] then
    _sessions[username_lower] = nil
    if log_debug then
      log_debug(function()
        return {
          action = "user_session_removed",
          username = username_lower
        }
      end)
    end
    return true
  end
  return false
end
local get_all_sessions
get_all_sessions = function()
  local result = { }
  local now = os.time()
  for username, session in pairs(_sessions) do
    if session.expires == nil or now <= session.expires then
      result[username] = session
    else
      _sessions[username] = nil
    end
  end
  return result
end
local cleanup_expired
cleanup_expired = function()
  local now = os.time()
  local count = 0
  for username, session in pairs(_sessions) do
    if session.expires and now > session.expires then
      _sessions[username] = nil
      count = count + 1
    end
  end
  if count > 0 and log_debug then
    log_debug(function()
      return {
        action = "user_session_cleanup",
        removed_count = count
      }
    end)
  end
  return count
end
return {
  init = init,
  add_session = add_session,
  get_session = get_session,
  is_authenticated = is_authenticated,
  refresh_session = refresh_session,
  remove_session = remove_session,
  get_all_sessions = get_all_sessions,
  cleanup_expired = cleanup_expired
}
