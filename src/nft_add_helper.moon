-- src/nft_add_helper.moon
-- Helper to try adding elements to nft with retries and backoff.

{ :ffi } = require "ffi_defs"
{ :NFT_ADD_RETRY_COUNT, :NFT_ADD_BACKOFF_MS } = require "config"
{ :log_warn } = require "log"

-- Pre-allocated timespec for backoff sleep (avoids allocation on each retry)
_timespec = ffi.new "timespec_t[1]"

-- Try calling fn(args...). Returns true if fn returned truthy within retries.
try_add_with_retries = (fn, ...) ->
  attempts = NFT_ADD_RETRY_COUNT or 6
  backoffs = NFT_ADD_BACKOFF_MS or {20, 50, 100, 200, 400, 800}

  for i = 1, attempts
    ok, err = fn ...
    return true if ok
    last_err = err
    if i < attempts
      ms = backoffs[i] or backoffs[#backoffs]
      _timespec[0].tv_sec = math.floor(ms / 1000)
      _timespec[0].tv_nsec = (ms % 1000) * 1000000
      pcall ffi.C.nanosleep, _timespec, nil
  args = {...}
  log_warn { action: "nft_add_retries_exhausted", attempts: attempts, err: last_err or "", arg1: args[1] or "", arg2: args[2] or "" }
  false

{ :try_add_with_retries }
