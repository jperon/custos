-- tools/quick_coverage_report.lua
-- Lit tmp/coverage_quick/quick_coverage.lua (produit par
-- tests/helpers/quick_coverage_setup.lua) et affiche :
--   - le nombre de lignes distinctes échantillonnées par fichier lua/
--   - la liste des fichiers jamais touchés (signal fiable malgré le
--     sous-échantillonnage : cf. AGENTS.md § Corrections d'audit)
--
-- Ce n'est PAS un pourcentage de couverture exact (luacov reste la référence
-- pour un chiffre précis sur un module isolé) : c'est un ordre de grandeur
-- rapide (~20 min pour toute la suite, contre >1h30 pour luacov complet).

local INCLUDE_PREFIX = "lua/"
local EXCLUDE_PATTERNS = {
  "^lua/ipparse/",
  "^lua/ffi_defs",
  "^lua/ffi_ndpi",
  "^lua/ffi_xxhash",
  "^lua/auth/ffi_socket",
  "^lua/auth/ffi_wolfssl",
}

local function included(src)
  if src:sub(1, #INCLUDE_PREFIX) ~= INCLUDE_PREFIX then return false end
  for _, pat in ipairs(EXCLUDE_PATTERNS) do
    if src:match(pat) then return false end
  end
  return true
end

local ok, seen = pcall(dofile, "tmp/coverage_quick/quick_coverage.lua")
if not ok then
  io.stderr:write("Impossible de lire tmp/coverage_quick/quick_coverage.lua (run 'make coverage-quick' d'abord)\n")
  os.exit(1)
end

local files = {}
local p = io.popen([[find lua -name "*.lua" -not -path "lua/ipparse/*" -not -name "ffi_defs*" -not -name "ffi_ndpi*" -not -name "ffi_xxhash*" -not -path "lua/auth/ffi_socket*" -not -path "lua/auth/ffi_wolfssl*"]])
for line in p:lines() do
  files[#files + 1] = line
end
p:close()
table.sort(files)

local zero = {}
print(string.format("%-55s %s", "fichier", "lignes échantillonnées"))
for _, f in ipairs(files) do
  local t = seen[f]
  local n = 0
  if t then
    for _ in pairs(t) do n = n + 1 end
  end
  print(string.format("%-55s %d", f, n))
  if n == 0 then zero[#zero + 1] = f end
end

print("")
print(string.format("%d fichiers lua/ (hors exclusions) au total, %d jamais touchés :", #files, #zero))
for _, f in ipairs(zero) do
  print("  " .. f)
end
