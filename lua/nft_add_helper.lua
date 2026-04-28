local ffi
ffi = require("ffi_defs").ffi
local NFT_ADD_RETRY_COUNT, NFT_ADD_BACKOFF_MS
do
  local _obj_0 = require("config")
  NFT_ADD_RETRY_COUNT, NFT_ADD_BACKOFF_MS = _obj_0.NFT_ADD_RETRY_COUNT, _obj_0.NFT_ADD_BACKOFF_MS
end
local _timespec = ffi.new("timespec_t[1]")
local try_add_with_retries
try_add_with_retries = function(fn, ...)
  local attempts = NFT_ADD_RETRY_COUNT or 3
  local backoffs = NFT_ADD_BACKOFF_MS or {
    20,
    50,
    100
  }
  for i = 1, attempts do
    local ok = fn(...)
    if ok then
      return true
    end
    if i < attempts then
      local ms = backoffs[i] or backoffs[#backoffs]
      _timespec[0].tv_sec = math.floor(ms / 1000)
      _timespec[0].tv_nsec = (ms % 1000) * 1000000
      pcall(ffi.C.nanosleep, _timespec, nil)
    end
  end
  return false
end
return {
  try_add_with_retries = try_add_with_retries
}
