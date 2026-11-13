_G.__COVERAGE__ = true
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

-- Primitives capturées AVANT le chargement des specs : certaines mockent
-- légitimement `io.open` (tests/unit/auth/cert_generator_spec.moon,
-- tests/unit/bridge_raw_spec.moon) avec un faux fichier qui n'a pas de `write`.
-- Le hook s'exécutant au milieu de ces mocks, utiliser le `io.open` global
-- faisait lever le flush périodique (« attempt to call method 'write' ») et
-- pouvait interrompre Busted avant son bilan, sans aucune erreur de test.
local io_open = io.open
local io_stderr = io.stderr
local os_clock = os.clock

dofile "tests/helpers/busted_setup.lua"

local coverage_filters = require "coverage_filters"

local seen = {}   -- [source] = { [line] = true }

local included = coverage_filters.included

-- Le flush est appelé depuis un hook `debug.sethook`, donc au milieu de code
-- arbitraire (specs, Busted, mocks de tests). Une exception qui s'en échappe
-- remonte dans l'appelant — y compris dans le médiateur d'événements de Busted
-- quand le hook s'y déclenche — et peut terminer le run AVANT la ligne de
-- synthèse (symptôme observé : 2651 `●`, pas de bilan, rc=1). L'échantillonneur
-- ne doit jamais influencer le déroulé des tests : toute erreur interne est
-- donc confinée ici et signalée une seule fois sur stderr.
local flush_error_reported = false

local function flush()
  local ok, err = pcall(function()
    local fh = io_open("tmp/coverage_quick/quick_coverage.lua", "w")
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
  end)
  if not ok and not flush_error_reported then
    flush_error_reported = true
    pcall(function()
      io_stderr:write("[coverage] flush ignoré : " .. tostring(err) .. "\n")
      io_stderr:flush()
    end)
  end
end

-- Flush périodique basé sur le temps plutôt que sur la fin de process : on ne
-- sait pas de façon fiable si/quand busted appelle os.exit (l'échec silencieux
-- de stats.out observé avec luacov sur le run complet en est un indice) — un
-- flush toutes les ~50 ms garantit des données sur disque quelle que soit la
-- façon dont le process se termine.
local last_flush = os_clock()
local FLUSH_PERIOD_S = 0.05

-- Hook "count" : appelé sans numéro de ligne (contrairement à un hook "l"),
-- il faut le lire via debug.getinfo(2, "Sl").currentline.
-- NB : ne PAS envelopper ce corps dans `pcall` : le hook serait alors appelé
-- depuis un frame C et `debug.getinfo(2)` désignerait `pcall` (source "=[C]"),
-- donc plus aucun échantillonnage. La seule I/O risquée (`flush`) est déjà
-- confinée par `pcall` ci-dessus ; le reste (getinfo, tables) ne peut pas lever.
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
  local now = os_clock()
  if now - last_flush >= FLUSH_PERIOD_S then
    last_flush = now
    flush()
  end
end

-- Échantillonne toutes les 50 instructions VM (count hook) : compromis
-- vitesse/représentativité. Plus petit = plus précis mais plus lent.
debug.sethook(hook, "", 50)

-- Filet de sécurité si le process termine proprement via os.exit.
local real_exit = os.exit
os.exit = function(...)
  debug.sethook()
  flush()
  real_exit(...)
end
