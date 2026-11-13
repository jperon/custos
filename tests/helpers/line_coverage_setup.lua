_G.__COVERAGE__ = true
-- tests/helpers/line_coverage_setup.lua
-- Collecte de couverture ligne-par-ligne pour `make coverage`.
--
-- Pourquoi ce helper ? Le hook de luacov (`luacov/hook.lua`) fait, à CHAQUE
-- événement de ligne, des opérations de chaîne (match/gsub) et une recherche
-- dans `runner.data`. Sur cette suite, il fait planter LuaJIT (SIGSEGV) dans
-- le parseur de formats d'ipparse (`lua/ipparse/lib/pack_compat_lib.lua`,
-- cf. docs/agents/audits.md § Corrections d'audit 2026-11-12) : le processus
-- meurt avant l'écriture des stats et `make coverage` échoue. Ce helper
-- installe un hook minimal qui enregistre EXACTEMENT les mêmes événements de
-- ligne (mêmes fichiers inclus/exclus via la configuration .luacov, mêmes
-- hits par ligne, format de stats luacov), mais sans les opérations de chaîne
-- par événement ; le rapport reste produit par `luacov`.
--
-- Utilisation (cible `coverage` du Makefile) :
--   busted ... --helper=tests/helpers/line_coverage_setup.lua tests/unit
-- puis :
--   luacov -c .luacov

dofile("tests/helpers/busted_setup.lua")

local runner = require "luacov.runner"
local stats = require "luacov.stats"

-- Recharge la configuration .luacov sans initialiser luacov (pas de hook ni de
-- wrapper os.exit de luacov) : on réutilise ainsi exactement les mêmes
-- include/exclude et le même fichier de stats que le rapport.
local config = runner.load_config(os.getenv("LUACOV_CONFIG") or ".luacov")
local statsfile = config.statsfile

-- Même normalisation que luacov/hook.lua.
local dir_sep = package.config:sub(1, 1)
if not dir_sep:find("[/\\]") then
  dir_sep = "/"
end

local data = {}
local seen = {}       -- info.source -> nom normalisé, ou false si exclu
local saved = false
local events = 0
local last_save = os.time()

local function save_now()
  local ok, err = pcall(stats.save, statsfile, data)
  if not ok then
    io.stderr:write("line_coverage_setup: échec d'écriture des stats: "
      .. tostring(err) .. "\n")
  end
end

local function on_exit()
  if saved then return end
  saved = true
  debug.sethook(nil)
  save_now()
end

-- Même boucle que luacov/hook.lua, sans string.match/gsub par événement.
debug.sethook(function(_, line_nr)
  local source = debug.getinfo(2, "S").source
  local name = seen[source]
  if name == nil then
    local prefixed = source:match("^@(.*)")
    if prefixed then
      prefixed = prefixed:gsub("^%.[/\\]", ""):gsub("[/\\]", dir_sep)
      if runner.file_included(prefixed) then
        name = prefixed
      else
        name = false
      end
    else
      name = false
    end
    seen[source] = name
  end
  if name == false then return end

  local file = data[name]
  if not file then
    file = { max = 0, max_hits = 0 }
    data[name] = file
  end
  if line_nr > file.max then
    file.max = line_nr
  end
  local hits = (file[line_nr] or 0) + 1
  file[line_nr] = hits
  if hits > file.max_hits then
    file.max_hits = hits
  end

  -- Sauvegarde périodique : un SIGSEGV intermittent de LuaJIT sous un hook de
  -- ligne (cf. en-tête) ne doit pas faire perdre toute la mesure ; au pire les
  -- dernières secondes.
  events = events + 1
  if events % 4096 == 0 then
    local now = os.time()
    if now - last_save >= 20 then
      last_save = now
      save_now()
    end
  end
end, "l")

-- Filet de sécurité : écrire les stats même si le processus sort par os.exit
-- (busted le fait en fin de run ; luacov enveloppe os.exit pour cette raison).
local raw_exit = os.exit
os.exit = function(...)
  on_exit()
  return raw_exit(...)
end

-- L'ancre doit rester référencée jusqu'à la fin du processus : un local de
-- chunk serait collecté dès le chargement du helper et écrirait des stats
-- vides (et couperait le hook).
if newproxy then
  _G.__line_coverage_anchor = newproxy(true)
  getmetatable(_G.__line_coverage_anchor).__gc = on_exit
end

-- Amorce des symboles FFI globaux (pollfd, socket, ...) pour les specs isolés,
-- comme line_coverage_batch_setup.lua : certains modules (nft_queue, worker_responses)
-- supposent lib.socket déjà chargé.
pcall(require, "lib.socket")
