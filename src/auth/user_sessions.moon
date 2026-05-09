-- src/auth/user_sessions.moon
-- User authentication session management.
--
-- Stores authenticated user sessions in-memory, mapping username → {src_ip, mac, timeout}.
-- Used by worker_auth_pipeline to track authenticated users based on TLS certificates.

{ :log_info, :log_warn, :log_debug } = require "log"

-- ── In-Memory Session Storage ────────────────────────────────────────

--- @class UserSession
-- @field username string Username extracted from certificate CN/SAN
-- @field src_ip string Source IP address (IPv4 or IPv6)
-- @field mac string Source MAC address
-- @field auth_time number Unix timestamp when user authenticated
-- @field expires number Unix timestamp when session expires (optional)

_sessions = {}
_session_timeout = 3600

--- Initialize user session manager with configuration.
-- @tparam number timeout Session timeout in seconds (default: 3600)
-- @treturn nil
init = (timeout) ->
  _session_timeout = timeout or 3600
  _sessions = {}

--- Add or update a user session.
-- @tparam string username Username (extracted from certificate)
-- @tparam string src_ip Source IP address
-- @tparam string mac Source MAC address
-- @treturn boolean true if added/updated successfully
add_session = (username, src_ip, mac) ->
  return false unless username and src_ip and mac
  
  username_lower = username\lower!
  now = os.time!
  
  _sessions[username_lower] = {
    username: username_lower
    src_ip: src_ip
    mac: mac\lower!
    auth_time: now
    expires: now + _session_timeout
  }
  
  if log_debug
    log_debug {
      action: "user_session_added"
      username: username_lower
      src_ip: src_ip
      mac: mac
      expires_in_s: _session_timeout
    }
  
  true

--- Get a user session by username.
-- @tparam string username Username to look up
-- @treturn table|nil Session table or nil if not found/expired
get_session = (username) ->
  return nil unless username
  
  username_lower = username\lower!
  session = _sessions[username_lower]
  
  return nil unless session
  
  now = os.time!
  if session.expires and now > session.expires
    _sessions[username_lower] = nil
    if log_debug
      log_debug {
        action: "user_session_expired"
        username: username_lower
      }
    return nil
  
  session

--- Check if a user is authenticated (for a given IP/MAC).
-- @tparam string username Username
-- @tparam string src_ip Source IP address (optional, for validation)
-- @tparam string mac Source MAC address (optional, for validation)
-- @treturn boolean true if user is authenticated and matches IP/MAC (if provided)
is_authenticated = (username, src_ip, mac) ->
  session = get_session username
  return false unless session
  
  if src_ip and session.src_ip ~= src_ip
    return false
  
  if mac and session.mac ~= mac\lower!
    return false
  
  true

--- Refresh a user session (extend timeout).
-- @tparam string username Username
-- @treturn boolean true if session was refreshed
refresh_session = (username) ->
  session = get_session username
  return false unless session
  
  now = os.time!
  session.expires = now + _session_timeout
  
  if log_debug
    log_debug {
      action: "user_session_refreshed"
      username: username\lower!
      expires_in_s: _session_timeout
    }
  
  true

--- Remove a user session.
-- @tparam string username Username
-- @treturn boolean true if session was removed
remove_session = (username) ->
  return false unless username
  
  username_lower = username\lower!
  if _sessions[username_lower]
    _sessions[username_lower] = nil
    if log_debug
      log_debug {
        action: "user_session_removed"
        username: username_lower
      }
    return true
  
  false

--- Get all active sessions (for debugging/logging).
-- @treturn table Table of {username → session}
get_all_sessions = ->
  result = {}
  now = os.time!
  
  for username, session in pairs _sessions
    if session.expires == nil or now <= session.expires
      result[username] = session
    else
      _sessions[username] = nil
  
  result

--- Clean up expired sessions.
-- @treturn number Count of removed sessions
cleanup_expired = ->
  now = os.time!
  count = 0
  
  for username, session in pairs _sessions
    if session.expires and now > session.expires
      _sessions[username] = nil
      count += 1
  
  if count > 0 and log_debug
    log_debug {
      action: "user_session_cleanup"
      removed_count: count
    }
  
  count

{
  :init
  :add_session
  :get_session
  :is_authenticated
  :refresh_session
  :remove_session
  :get_all_sessions
  :cleanup_expired
}
