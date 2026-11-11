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

local coverage_filters = require "coverage_filters"

local ok, seen = pcall(dofile, "tmp/coverage_quick/quick_coverage.lua")
if not ok then
  io.stderr:write("Impossible de lire tmp/coverage_quick/quick_coverage.lua (run 'make coverage-quick' d'abord)\n")
  os.exit(1)
end

local files = {}
local p = io.popen([[find lua -name "*.lua"]])
for line in p:lines() do
  if coverage_filters.included(line) then
    files[#files + 1] = line
  end
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
