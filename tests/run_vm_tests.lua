-- tests/run_vm_tests.lua
-- Lance tous les specs Busted-compatibles de tests/unit/ via mini_busted.
-- Conçu pour tourner sur la VM custos avec LuaJIT seul (aucune dépendance
-- luarocks ; busted n'est pas disponible sur OpenWrt 25.12).

-- Chemins relatifs au dossier de déploiement de la VM (cf. homelab.sh test-unit).
-- Inclut /usr/lib/lua pour trouver les rocks OpenWrt (lyaml, etc.).
package.path = table.concat({
  "lua/?.lua",
  "lua/?/init.lua",
  "tests/?.lua",
  "tests/helpers/?.lua",
  "/usr/lib/lua/?.lua",
  "/usr/lib/lua/?/init.lua",
  package.path,
}, ";")
package.cpath = table.concat({
  "/usr/lib/lua/?.so",
  package.cpath,
}, ";")

-- Helper Busted standard du projet (stubs ffi_defs, config, log…).
dofile("tests/helpers/busted_setup.lua")

local mini = require "mini_busted"
mini.install()

-- ── Découverte des specs ────────────────────────────────────────────

local function list_specs(dir, out)
  out = out or {}
  local pipe = io.popen("find '"..dir.."' -name '*_spec.lua' -type f 2>/dev/null | sort")
  if not pipe then return out end
  for line in pipe:lines() do out[#out+1] = line end
  pipe:close()
  return out
end

local specs = list_specs("tests/unit")
io.write(string.format("[mini_busted] %d specs trouvés\n\n", #specs))

-- Snapshot de package.loaded : on isole chaque spec pour qu'un stub posé
-- via package.loaded[...] = {...} ne contamine pas les specs suivants.
local function snapshot_loaded()
  local snap = {}
  for k, v in pairs(package.loaded) do snap[k] = v end
  return snap
end
local function restore_loaded(snap)
  for k in pairs(package.loaded) do
    if snap[k] == nil then package.loaded[k] = nil end
  end
  for k, v in pairs(snap) do package.loaded[k] = v end
end

local baseline = snapshot_loaded()
-- Debug optionnel : afficher ce qui est dans baseline
if os.getenv("DEBUG_BASELINE") then
  for k in pairs(baseline) do io.write("[baseline] "..k.."\n") end
end
local file_errors = 0
for _, spec in ipairs(specs) do
  local ok, err = pcall(dofile, spec)
  if not ok then
    file_errors = file_errors + 1
    io.write("✗ erreur de chargement : "..spec.."\n  "..tostring(err).."\n")
  end
  restore_loaded(baseline)
end

local rc = mini.run()
if file_errors > 0 then
  io.write(string.format("\nFichiers en erreur de chargement : %d\n", file_errors))
  rc = 1
end
os.exit(rc)
