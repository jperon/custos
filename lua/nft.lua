local ffi, libnft
do
  local _obj_0 = require("ffi_defs")
  ffi, libnft = _obj_0.ffi, _obj_0.libnft
end
local config = require("config")
local log_warn, log_error
do
  local _obj_0 = require("log")
  log_warn, log_error = _obj_0.log_warn, _obj_0.log_error
end
local ctx = libnft.nft_ctx_new(0)
if ctx == nil then
  error("nft_ctx_new() échoué")
end
local ok_buf = pcall(function()
  return libnft.nft_ctx_buffer_error(ctx)
end)
local get_error_buffer
get_error_buffer = function()
  if not (ok_buf) then
    return nil
  end
  local ok, ptr = pcall(function()
    return libnft.nft_ctx_get_error_buffer(ctx)
  end)
  if not (ok and ptr ~= nil) then
    return nil
  end
  local msg = ffi.string(ptr)
  if msg and msg ~= "" then
    return msg
  end
end
local run_cmd
run_cmd = function(cmd, opts)
  if opts == nil then
    opts = nil
  end
  local rc = libnft.nft_run_cmd_from_buffer(ctx, cmd)
  if rc ~= 0 then
    local ts = os.time()
    local nft_err = get_error_buffer()
    local busy = nft_err and nft_err:match("Resource busy")
    if not (opts and opts.quiet) then
      log_warn(function()
        return {
          action = "nft_cmd_failed",
          cmd = cmd,
          rc = rc,
          ts = ts,
          nft_err = nft_err or "",
          transient = busy and "resource_busy" or ""
        }
      end)
    end
    return false, nft_err
  end
  return true, nil
end
local cleanup
cleanup = function()
  if ctx ~= nil then
    return libnft.nft_ctx_free(ctx)
  end
end
return {
  run_cmd = run_cmd,
  cleanup = cleanup
}
