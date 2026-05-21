local ffi
ffi = require("ffi_defs").ffi
local config = require("config")
local log_warn
log_warn = require("log").log_warn
local _timespec = ffi.new("timespec_t[1]")
local try_add_with_retries
try_add_with_retries = function(fn, ...)
  local backoffs = config.nft.add_backoff_ms or {
    20,
    50,
    100,
    200,
    400,
    800
  }
  for i = 1, #backoffs do
    local ok, err = fn(...)
    if ok then
      return true
    end
    local last_err = err
    if i < #backoffs then
      local ms = backoffs[i] or backoffs[#backoffs]
      _timespec[0].tv_sec = math.floor(ms / 1000)
      _timespec[0].tv_nsec = (ms % 1000) * 1000000
      pcall(ffi.C.nanosleep, _timespec, nil)
    end
  end
  local args = {
    ...
  }
  log_warn({
    action = "nft_add_retries_exhausted",
    attempts = #backoffs,
    err = last_err or "",
    arg1 = args[1] or "",
    arg2 = args[2] or ""
  })
  return false
end
return {
  try_add_with_retries = try_add_with_retries
}
