-- src/ffi_xxhash.moon
-- Façade FFI libxxhash : expose xxh64(str) → uint64_t cdata.
-- Utilise uint64_t natif (pas tonumber) pour éviter la perte de précision
-- sur les valeurs > 2⁵³.

ffi = require "ffi"

ffi.cdef [[
  typedef unsigned long long XXH64_hash_t;
  XXH64_hash_t XXH64(const void* input, size_t length, unsigned long long seed);
]]

-- Essaie d'abord le soname versionné (paquet runtime), puis le nom court.
local xxhash_lib
do
  ok, lib = pcall ffi.load, "xxhash.so.0"
  unless ok
    ok, lib = pcall ffi.load, "xxhash"
  error "libxxhash introuvable (apt install libxxhash0)" unless ok
  xxhash_lib = lib

--- Calcule le hash XXH64 d'une chaîne Lua.
-- Retourne un cdata uint64_t (pas de tonumber → précision totale sur 64 bits).
-- @tparam string s Chaîne à hacher
-- @treturn cdata XXH64_hash_t (uint64_t)
xxh64 = (s) ->
  xxhash_lib.XXH64 s, #s, 0ULL

{ :xxh64 }
