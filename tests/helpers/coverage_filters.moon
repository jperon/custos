-- tests/helpers/coverage_filters.moon
-- Critères d'inclusion communs à la couverture rapide : partagés par le hook
-- (tests/helpers/quick_coverage_setup.lua) et le rapport
-- (tools/quick_coverage_report.lua), pour qu'une seule liste soit à tenir à jour.
--
-- INCLUDE_PREFIX : seuls les fichiers sous lua/ sont instrumentés.
-- EXCLUDE_PATTERNS : code généré / sous-modules / bindings FFI, exclus des deux
-- côtés (sinon le hook et le rapport divergent sur les fichiers « jamais
-- touchés »).

M = {}

M.INCLUDE_PREFIX = "lua/"
M.EXCLUDE_PATTERNS = {
  "^lua/ipparse/"
  "^lua/ffi_defs"
  "^lua/ffi_ndpi"
  "^lua/ffi_xxhash"
  "^lua/auth/ffi_socket"
  "^lua/auth/ffi_wolfssl"
}

--- Indique si un fichier source doit être pris en compte.
-- @tparam string src chemin du fichier (ex. "lua/doh/query.lua")
-- @treturn boolean true si le fichier est inclus dans la couverture
included = (src) ->
  return false if src\sub(1, #M.INCLUDE_PREFIX) != M.INCLUDE_PREFIX
  for _, pat in ipairs M.EXCLUDE_PATTERNS
    return false if src\match pat
  true

M.included = included

M
