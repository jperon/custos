-- tests/helpers/quick_coverage_setup.lua
-- Alternative légère à luacov pour un ordre de grandeur rapide de couverture.
--
-- luacov instrumente CHAQUE ligne exécutée via debug.sethook(..., "l") : sur
-- cette suite (packet parsing / boucles denses), le coût est ~40x le temps
-- normal (>1h). Un hook "l" ou un hook "count" désactivent tous les deux le
-- JIT LuaJIT (limitation connue : tout hook actif coupe la compilation JIT,
-- quel que soit son masque) — mais un hook "count" (déclenché tous les N
-- instructions VM) est appelé BEAUCOUP moins souvent qu'un hook "l" (déclenché
-- à CHAQUE ligne exécutée). Résultat : un échantillonnage statistique des
-- lignes atteintes, pas une couverture exacte — mais un ordre de grandeur
-- utilisable, à un coût proche du run normal (`make test`, ~100s).
--
-- Biais connu : sous-estime la couverture réelle (une ligne exécutée entre
-- deux échantillons n'est jamais vue). Calibré contre le vrai chiffre luacov
-- sur lua/ipc.lua (85.04%, tests/unit/ipc) pour estimer l'ampleur du biais.

dofile "tests/helpers/busted_setup.lua"

local INCLUDE_PREFIX = "lua/"
local EXCLUDE_PATTERNS = {
  "^lua/ipparse/",
  "^lua/ffi_defs",
  "^lua/ffi_ndpi",
  "^lua/ffi_xxhash",
  "^lua/auth/ffi_socket",
  "^lua/auth/ffi_wolfssl",
}

local seen = {}   -- [source] = { [line] = true }

local function included(src)
  if src:sub(1, #INCLUDE_PREFIX) ~= INCLUDE_PREFIX then return false end
  for _, pat in ipairs(EXCLUDE_PATTERNS) do
    if src:match(pat) then return false end
  end
  return true
end

local function flush()
  local fh = io.open("tmp/coverage_quick/quick_coverage.lua", "w")
  if not fh then return end
  fh:write("return {\n")
  for src, lines in pairs(seen) do
    fh:write(string.format("  [%q] = {", src))
    for line in pairs(lines) do
      fh:write(tostring(line) .. ",")
    end
    fh:write("},\n")
  end
  fh:write("}\n")
  fh:close()
end

-- Flush périodique basé sur le temps plutôt que sur la fin de process : on ne
-- sait pas de façon fiable si/quand busted appelle os.exit (l'échec silencieux
-- de stats.out observé avec luacov sur le run complet en est un indice) — un
-- flush toutes les ~3s garantit des données sur disque quelle que soit la
-- façon dont le process se termine.
local last_flush = os.clock()
local FLUSH_PERIOD_S = 0.05

-- Hook "count" : appelé sans numéro de ligne (contrairement à un hook "l"),
-- il faut le lire via debug.getinfo(2, "Sl").currentline.
local function hook()
  local info = debug.getinfo(2, "Sl")
  if info and info.source and info.source:sub(1, 1) == "@" then
    local line = info.currentline
    if line and line >= 0 then
      local src = info.source:sub(2)
      if included(src) then
        local t = seen[src]
        if not t then
          t = {}
          seen[src] = t
        end
        t[line] = true
      end
    end
  end
  local now = os.clock()
  if now - last_flush >= FLUSH_PERIOD_S then
    last_flush = now
    flush()
  end
end

-- Échantillonne toutes les 500 instructions VM (count hook) : compromis
-- vitesse/représentativité. Plus petit = plus précis mais plus lent.
debug.sethook(hook, "", 50)

-- Filet de sécurité si le process termine proprement via os.exit.
local real_exit = os.exit
os.exit = function(...)
  debug.sethook()
  flush()
  real_exit(...)
end
