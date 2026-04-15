-- src/nft_add_helper.moon
-- Helper to try adding elements to nft with retries and backoff.

{ :ffi } = require "ffi_defs"
{ :NFT_ADD_RETRY_COUNT, :NFT_ADD_BACKOFF_MS } = require "config"

-- Try calling fn(args...). Returns true if fn returned truthy within retries.
try_add_with_retries = (fn, ...) ->
  attempts = NFT_ADD_RETRY_COUNT or 3
  backoffs = NFT_ADD_BACKOFF_MS or {20, 50, 100}

  for i in [1..attempts]
    ok = fn ...
    return true if ok
    if i < attempts
      ms = backoffs[i] or backoffs[#backoffs]
      -- Prefer nanosleep when available (ffi.C.nanosleep). Fallback to os.execute.
      has_nanosleep = false
      pcall ->
        if ffi and ffi.C then local _ = ffi.C.nanosleep end
        has_nanosleep = true
      if has_nanosleep
        req = ffi.new "timespec_t[1]"
        req[0].tv_sec = math.floor(ms / 1000)
        req[0].tv_nsec = (ms % 1000) * 1000000
        pcall ffi.C.nanosleep, req, nil
      else
        -- fallback: coarse sleep
        os.execute "sleep #{ms / 1000}"
  false

{ :try_add_with_retries }