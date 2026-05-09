local log_info, log_warn, log_debug, log_error, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug, log_error, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug, _obj_0.log_error, _obj_0.set_action_prefix
end
local user_sessions = require("auth.user_sessions")
local init_sessions = user_sessions.init
local add_session = user_sessions.add_session
local get_session = user_sessions.get_session
local cleanup_expired = user_sessions.cleanup_expired
local extract_username, validate_username
do
  local _obj_0 = require("auth.cert_parser")
  extract_username, validate_username = _obj_0.extract_username, _obj_0.validate_username
end
local ipc = require("ipc")
local _cfg = { }
local _nft_wfd = nil
local _action_prefix_set = false
local init
init = function(cfg, nft_wfd)
  _cfg = cfg or { }
  _nft_wfd = nft_wfd
  if not (_action_prefix_set) then
    if set_action_prefix then
      set_action_prefix("auth_pipeline_")
    end
    _action_prefix_set = true
  end
  local auth_cfg = _cfg.auth or { }
  local session_timeout = auth_cfg.session_timeout or auth_cfg.session_ttl or 3600
  local user_field = auth_cfg.user_field or "subject"
  init_sessions(session_timeout)
  if log_info then
    return log_info({
      action = "init",
      session_timeout = session_timeout,
      user_field = user_field
    })
  end
end
local process_tls_certificate
process_tls_certificate = function(tls_data)
  if not (tls_data) then
    return false, "missing tls_data"
  end
  local cert_data = tls_data.certificate or tls_data.cert
  local src_ip = tls_data.src_ip
  local mac = tls_data.mac
  if not (cert_data) then
    return false, "missing certificate data"
  end
  if not (src_ip) then
    return false, "missing source IP"
  end
  local auth_cfg = _cfg.auth or { }
  local user_field = auth_cfg.user_field or "subject"
  local username = extract_username(cert_data, user_field)
  if not (username) then
    if log_warn then
      log_warn({
        action = "username_extraction_failed",
        cert_subject = cert_data.subject or "unknown"
      })
    end
    return false, "unable to extract username from certificate"
  end
  if not (validate_username(username)) then
    if log_warn then
      log_warn({
        action = "username_validation_failed",
        username = username
      })
    end
    return false, "invalid username format"
  end
  mac = mac or "unknown"
  local success = add_session(username, src_ip, mac)
  if success then
    if log_info then
      log_info({
        action = "user_authenticated",
        username = username,
        src_ip = src_ip,
        mac = mac
      })
    end
    if _nft_wfd and _nft_wfd >= 0 then
      send_user_auth_to_nft(username, src_ip, mac)
    end
    return true, nil
  else
    if log_warn then
      log_warn({
        action = "session_creation_failed",
        username = username
      })
    end
    return false, "unable to create user session"
  end
end
local send_user_auth_to_nft
send_user_auth_to_nft = function(username, src_ip, mac)
  if not (_nft_wfd and _nft_wfd >= 0) then
    return false
  end
  local msg = "user_auth\t" .. tostring(username) .. "\t" .. tostring(src_ip) .. "\t" .. tostring(mac) .. "\n"
  local n
  if _nft_wfd then
    n = io.write(msg)
  end
  if n then
    return n > 0
  end
  return false
end
local periodic_cleanup
periodic_cleanup = function()
  return cleanup_expired()
end
local get_user_session
get_user_session = function(username)
  return get_session(username)
end
local run
run = function()
  log_info({
    action = "worker_started"
  })
  while true do
    periodic_cleanup()
    os.execute("sleep 60")
  end
end
return {
  init = init,
  process_tls_certificate = process_tls_certificate,
  send_user_auth_to_nft = send_user_auth_to_nft,
  periodic_cleanup = periodic_cleanup,
  get_user_session = get_user_session,
  run = run
}
