-- src/ffi_xxhash.moon
-- Façade FFI libxxhash : expose xxh64(str) → uint64_t cdata.
-- Utilise uint64_t natif (pas tonumber) pour éviter la perte de précision
-- sur les valeurs > 2⁵³.

ffi = require "ffi"

ffi.cdef [[
  typedef unsigned long long XXH64_hash_t;
  XXH64_hash_t XXH64(const void* input, size_t length, unsigned long long seed);
]]

local xxhash_lib
do
  -- Stratégie 1 : soname versionné ou nom court (ldconfig / LD_LIBRARY_PATH standard)
  for _, name in ipairs({"xxhash.so.0", "xxhash", "libxxhash.so.0", "libxxhash.so"})
    ok, lib = pcall ffi.load, name
    if ok
      xxhash_lib = lib
      break

  -- Stratégie 2 : recherche dans LD_LIBRARY_PATH puis chemins standards
  unless xxhash_lib
    dirs = {}
    for p in (os.getenv("LD_LIBRARY_PATH") or "")\gmatch("[^:]+")
      dirs[#dirs + 1] = p
    for _, p in ipairs({"/usr/lib", "/lib", "/usr/local/lib"})
      dirs[#dirs + 1] = p
    search = table.concat(dirs, " ")
    f = io.popen("find #{search} -name 'libxxhash*.so*' -type f 2>/dev/null | sort -V | tail -1")
    if f
      path = f\read("*a")\gsub("\n", "")
      f\close!
      if path ~= ""
        ok, lib = pcall ffi.load, path
        xxhash_lib = lib if ok

  -- Réinitialise l'entrée package.loaded pour éviter la cascade
  -- "loop or previous error" sur les require() suivants.
  unless xxhash_lib
    package.loaded["ffi_xxhash"] = nil
    error "libxxhash introuvable"

--- Calcule le hash XXH64 d'une chaîne Lua.
-- Retourne un cdata uint64_t (pas de tonumber → précision totale sur 64 bits).
-- @tparam string s Chaîne à hacher
-- @treturn cdata XXH64_hash_t (uint64_t)
xxh64 = (s) ->
  xxhash_lib.XXH64 s, #s, 0ULL

{ :xxh64 }
