-- tools/merge_luacov_stats.lua
-- Fusionne plusieurs fichiers de statistiques luacov (format
-- "max:chemin" puis une valeur de hits par ligne) en un seul, en sommant
-- les hits ligne par ligne et en prenant le max des numéros de ligne.
--
-- Utilisation :
--   luajit tools/merge_luacov_stats.lua <sortie> <entrée1> <entrée2> ...
--
-- Sert à la cible `make coverage-split` : couverture luacov exacte même
-- lorsque la suite complète en un seul processus perd ses stats en fin de
-- run (cf. docs/agents/audits.md § Corrections d'audit 2026-11-12).

local stats = require "luacov.stats"

local out_path = arg[1]
if not out_path or not arg[2] then
  io.stderr:write("usage: luajit tools/merge_luacov_stats.lua <sortie> <entrée...>\n")
  os.exit(1)
end

local merged = {}
local nfiles = 0

for i = 2, #arg do
  local data = stats.load(arg[i])
  if not data then
    io.stderr:write("merge_luacov_stats: impossible de lire " .. arg[i] .. "\n")
    os.exit(1)
  end
  nfiles = nfiles + 1
  for name, filedata in pairs(data) do
    local dst = merged[name]
    if not dst then
      merged[name] = filedata
    else
      dst.max = math.max(dst.max, filedata.max)
      dst.max_hits = math.max(dst.max_hits or 0, filedata.max_hits or 0)
      for line, hits in pairs(filedata) do
        -- Les clés "max"/"max_hits" sont des chaînes : seules les clés
        -- numériques portent des hits.
        if type(line) == "number" then
          dst[line] = (dst[line] or 0) + hits
          if dst[line] > dst.max_hits then
            dst.max_hits = dst[line]
          end
        end
      end
    end
  end
end

stats.save(out_path, merged)
io.stderr:write(string.format("merge_luacov_stats: %d fichier(s) fusionné(s) → %s\n",
  nfiles, out_path))
