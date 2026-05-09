-- src/worker_auth_pipeline.moon
-- User authentication pipeline worker.
--
-- Processes authenticated users from TLS certificates (ClientHello).
-- Extracts username from certificate CN/SAN and maintains user session state.
-- Updates nftables set with authenticated users for rule evaluation.
--
-- Input: Authenticated TLS connection data from worker_tls or auth/server
-- Output: User sessions in-memory + IPC to worker_nft (set updates)

{ :log_info, :log_warn, :log_debug, :log_error, :set_action_prefix } = require "log"
user_sessions = require "auth.user_sessions"
init_sessions = user_sessions.init
add_session = user_sessions.add_session
get_session = user_sessions.get_session
cleanup_expired = user_sessions.cleanup_expired
{ :extract_username, :validate_username } = require "auth.cert_parser"
ipc = require "ipc"

set_action_prefix "auth_pipeline_"

-- Configuration
_cfg = {}
_nft_wfd = nil

--- Initialize the authentication pipeline worker.
-- @tparam table cfg Configuration with auth settings
-- @tparam number nft_wfd File descriptor for writing to worker_nft (optional)
-- @treturn nil
init = (cfg, nft_wfd) ->
  _cfg = cfg or {}
  _nft_wfd = nft_wfd
  
  auth_cfg = _cfg.auth or {}
  session_timeout = auth_cfg.session_timeout or auth_cfg.session_ttl or 3600
  user_field = auth_cfg.user_field or "subject"
  
  init_sessions session_timeout
  
  log_info {
    action: "init"
    session_timeout: session_timeout
    user_field: user_field
  }

--- Process a TLS client certificate for user authentication.
-- Extracts username from certificate and creates user session.
-- @tparam table tls_data TLS handshake data with certificate info
-- @treturn boolean, string|nil true if user authenticated, or false + reason
process_tls_certificate = (tls_data) ->
  return false, "missing tls_data" unless tls_data
  
  -- Extract certificate data
  cert_data = tls_data.certificate or tls_data.cert
  src_ip = tls_data.src_ip
  mac = tls_data.mac
  
  return false, "missing certificate data" unless cert_data
  return false, "missing source IP" unless src_ip
  
  -- Extract username from certificate
  auth_cfg = _cfg.auth or {}
  user_field = auth_cfg.user_field or "subject"
  username = extract_username cert_data, user_field
  
  unless username
    log_warn {
      action: "username_extraction_failed"
      cert_subject: cert_data.subject or "unknown"
    }
    return false, "unable to extract username from certificate"
  
  unless validate_username username
    log_warn {
      action: "username_validation_failed"
      username: username
    }
    return false, "invalid username format"
  
  -- Create user session
  mac = mac or "unknown"
  success = add_session username, src_ip, mac
  
  if success
    log_info {
      action: "user_authenticated"
      username: username
      src_ip: src_ip
      mac: mac
    }
    
    -- Notify nftables worker to add user to authenticated set
    if _nft_wfd and _nft_wfd >= 0
      send_user_auth_to_nft username, src_ip, mac
    
    return true, nil
  else
    log_warn {
      action: "session_creation_failed"
      username: username
    }
    return false, "unable to create user session"

--- Send authenticated user info to nftables worker.
-- Format: username string + src_ip string + mac string (IPC message)
-- @tparam string username Authenticated username
-- @tparam string src_ip Source IP address
-- @tparam string mac Source MAC address
-- @treturn boolean true if sent successfully
send_user_auth_to_nft = (username, src_ip, mac) ->
  return false unless _nft_wfd and _nft_wfd >= 0
  
  -- Build IPC message: action=user_auth, username, src_ip, mac
  msg = "user_auth\t#{username}\t#{src_ip}\t#{mac}\n"
  
  n = io.write msg if _nft_wfd
  return n > 0 if n
  
  false

--- Periodic cleanup of expired sessions.
-- Should be called periodically (e.g., every 60 seconds).
-- @treturn number Count of expired sessions removed
periodic_cleanup = () ->
  cleanup_expired!

--- Get current user session info (for debugging/monitoring).
-- @tparam string username Username to look up
-- @treturn table|nil Session info or nil if not found
get_user_session = (username) ->
  get_session username

--- Worker main loop stub (for testing).
-- In production, this would be integrated with supervisor/main.moon
-- @treturn nil
run = ->
  log_info { action: "worker_started" }
  
  -- Main loop would process TLS certificate data here
  -- and call process_tls_certificate for each connection
  
  while true
    -- Periodic cleanup
    periodic_cleanup!
    os.execute "sleep 60"

{
  :init
  :process_tls_certificate
  :send_user_auth_to_nft
  :periodic_cleanup
  :get_user_session
  :run
}
