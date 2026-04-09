local load_or_generate
load_or_generate = require("auth.cert").load_or_generate
local load_secrets
load_secrets = require("auth.credentials").load_secrets
local run
run = require("auth.server").run
local log_info, log_warn, log_error
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error
end
local ffi = require("ffi")
ffi.cdef([[  typedef void (*sighandler_t)(int);
  sighandler_t signal(int signum, sighandler_t handler);
]])
local SIGHUP = 1
local _reload_requested = false
local run_auth_worker
run_auth_worker = function(auth_cfg)
  local cert_path = auth_cfg.cert or "./tmp/auth.crt"
  local key_path = auth_cfg.key or "./tmp/auth.key"
  log_info({
    action = "auth_worker_start",
    port = auth_cfg.port
  })
  local tls_ctx = load_or_generate(key_path, cert_path)
  log_info({
    action = "auth_cert_loaded",
    cert = cert_path
  })
  local secrets_path = auth_cfg.secrets or "cfg/secrets"
  local secrets, err = load_secrets(secrets_path)
  if not (secrets) then
    log_error({
      action = "auth_secrets_load_failed",
      err = err
    })
    secrets = { }
  end
  local n_users = 0
  for _ in pairs(secrets) do
    n_users = n_users + 1
  end
  log_info({
    action = "auth_secrets_loaded",
    path = secrets_path,
    users = n_users
  })
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
      log_info({
        action = "auth_secrets_reloaded",
        path = secrets_path
      })
      return new_secrets
    else
      log_warn({
        action = "auth_secrets_reload_failed",
        err = err2
      })
      return nil
    end
  end
  return run(tls_ctx, secrets, auth_cfg, reload_fn)
end
return {
  run_auth_worker = run_auth_worker
}
