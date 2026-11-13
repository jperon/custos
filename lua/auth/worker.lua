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
local create_watcher
create_watcher = require("lib.sighup").create_watcher
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
  local watcher_ok, watcher = pcall(create_watcher)
  if not (watcher_ok) then
    log_error(function()
      return {
        action = "sighup_watch_failed",
        err = tostring(watcher)
      }
    end)
    watcher = nil
  end
  local reload_fn
  reload_fn = function()
    if not (watcher and watcher:pending()) then
      return nil
    end
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
