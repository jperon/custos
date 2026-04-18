local ffi = require("ffi")
ffi.cdef([[  typedef unsigned long long XXH64_hash_t;
  XXH64_hash_t XXH64(const void* input, size_t length, unsigned long long seed);
]])
local xxhash_lib
do
  local ok, lib = pcall(ffi.load, "xxhash.so.0")
  if not (ok) then
    ok, lib = pcall(ffi.load, "xxhash")
  end
  if not (ok) then
    error("libxxhash introuvable (apt install libxxhash0)")
  end
  xxhash_lib = lib
end
local xxh64
xxh64 = function(s)
  return xxhash_lib.XXH64(s, #s, 0ULL)
end
return {
  xxh64 = xxh64
}
