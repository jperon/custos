local ffi = require("ffi")
ffi.cdef([[  typedef unsigned long long XXH64_hash_t;
  XXH64_hash_t XXH64(const void* input, size_t length, unsigned long long seed);
]])
local xxhash_lib
do
  for _, name in ipairs({
    "xxhash.so.0",
    "xxhash",
    "libxxhash.so.0",
    "libxxhash.so"
  }) do
    local ok, lib = pcall(ffi.load, name)
    if ok then
      xxhash_lib = lib
      break
    end
  end
  if not (xxhash_lib) then
    local dirs = { }
    for p in (os.getenv("LD_LIBRARY_PATH") or ""):gmatch("[^:]+") do
      dirs[#dirs + 1] = p
    end
    for _, p in ipairs({
      "/usr/lib",
      "/lib",
      "/usr/local/lib"
    }) do
      dirs[#dirs + 1] = p
    end
    local search = table.concat(dirs, " ")
    local f = io.popen("find " .. tostring(search) .. " -name 'libxxhash*.so*' -type f 2>/dev/null | sort -V | tail -1")
    if f then
      local path = f:read("*a"):gsub("\n", "")
      f:close()
      if path ~= "" then
        local ok, lib = pcall(ffi.load, path)
        if ok then
          xxhash_lib = lib
        end
      end
    end
  end
  if not (xxhash_lib) then
    package.loaded["ffi_xxhash"] = nil
    error("libxxhash introuvable")
  end
end
local xxh64
xxh64 = function(s)
  return xxhash_lib.XXH64(s, #s, 0ULL)
end
return {
  xxh64 = xxh64
}
