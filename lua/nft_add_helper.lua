-- lua/nft_add_helper.lua
local ffi_defs = require "ffi_defs"
local ffi = ffi_defs.ffi
local cfg = require "config"

local NFT_ADD_RETRY_COUNT = cfg.NFT_ADD_RETRY_COUNT or 3
local NFT_ADD_BACKOFF_MS = cfg.NFT_ADD_BACKOFF_MS or {20,50,100}

local function try_add_with_retries(fn, ...)
  local attempts = NFT_ADD_RETRY_COUNT
  local backoffs = NFT_ADD_BACKOFF_MS
  for i = 1, attempts do
    local ok = fn(...)
    if ok then return true end
    if i < attempts then
      local ms = backoffs[i] or backoffs[#backoffs]
      local has_nanosleep = false
      pcall(function()
        if ffi and ffi.C then local _ = ffi.C.nanosleep end
        has_nanosleep = true
      end)
      if has_nanosleep then
        local req = ffi.new("timespec_t[1]")
        req[0].tv_sec = math.floor(ms / 1000)
        req[0].tv_nsec = (ms % 1000) * 1000000
        pcall(ffi.C.nanosleep, req, nil)
      else
        os.execute("sleep " .. (ms / 1000))
      end
    end
  end
  return false
end

return { try_add_with_retries = try_add_with_retries }
