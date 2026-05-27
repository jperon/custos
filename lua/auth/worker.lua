local load_secrets
load_secrets = require("auth.credentials").load_secrets
local run
run = require("auth.server").run
local nft_sess = require("auth.nft_sessions")
local log_info, log_warn, log_error, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error, _obj_0.set_action_prefix
end
local ffi = require("ffi")
local SIGHUP = 1
local _reload_requested = false
local run_auth_worker
run_auth_worker = function(auth_cfg)
  set_action_prefix("auth_")
  log_info(function()
    return {
      action = "worker_start",
      port = auth_cfg.port
    }
  end)
  local secrets_path = auth_cfg.secrets or "/etc/custos/secrets"
  local secrets, err = load_secrets(secrets_path)
  if not (secrets) then
    log_error(function()
      return {
        action = "secrets_load_failed",
        path = secrets_path,
        err = err
      }
    end)
    secrets = { }
  end
  local n_users = 0
  for _ in pairs(secrets) do
    n_users = n_users + 1
  end
  log_info(function()
    return {
      action = "secrets_loaded",
      path = secrets_path,
      users = n_users
    }
  end)
  ffi.C.signal(SIGHUP, ffi.cast("sighandler_t", function()
    _reload_requested = true
  end))
  local reload_fn
  reload_fn = function()
    if not (_reload_requested) then
      return nil
    end
    _reload_requested = false
    local new_secrets, err2 = load_secrets(secrets_path)
    if new_secrets then
      log_info(function()
        return {
          action = "secrets_reloaded",
          path = secrets_path
        }
      end)
      return new_secrets
    else
      log_warn(function()
        return {
          action = "secrets_reload_failed",
          path = secrets_path,
          err = err2
        }
      end)
      return nil
    end
  end
  return run(secrets, auth_cfg, reload_fn, nft_sess, secrets_path)
end
return {
  run_auth_worker = run_auth_worker
}
