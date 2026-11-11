local M = { }
M.INCLUDE_PREFIX = "lua/"
M.EXCLUDE_PATTERNS = {
  "^lua/ipparse/",
  "^lua/moonscript/",
  "^lua/moon/",
  "^lua/ffi_defs",
  "^lua/ffi_ndpi",
  "^lua/ffi_xxhash",
  "^lua/auth/ffi_socket",
  "^lua/auth/ffi_wolfssl"
}
local included
included = function(src)
  if src:sub(1, #M.INCLUDE_PREFIX) ~= M.INCLUDE_PREFIX then
    return false
  end
  for _, pat in ipairs(M.EXCLUDE_PATTERNS) do
    if src:match(pat) then
      return false
    end
  end
  return true
end
M.included = included
return M
