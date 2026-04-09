-- src/filter/conditions/to_domainlist.moon
-- Condition : le domaine demandé (ou un suffixe) se trouve dans une liste
-- de domaines précompilée.
--
-- Contrairement à shelterfilter :
--   • Pas de fork : la DB est chargée en mémoire dans le même processus.
--   • Pas de tonumber() : uint64_t natif (FFI cdata) → précision totale.
--   • Format .bin : N × 8 octets uint64_t little-endian, sans en-tête.
--   • Format .domains (texte, un domaine par ligne) : chargé et haché
--     à la volée au démarrage (utile en développement).

ffi  = require "ffi"

--- Charge une liste de domaines depuis un fichier .bin ou .domains.
-- @tparam string path Chemin vers le fichier
-- @treturn cdata, number Tableau uint64_t[] et nombre d'entrées, ou nil, msg
local load_list
load_list = (path) ->
  xxhash = require "ffi_xxhash"
  bsearch_m = require "filter.lib.bsearch"

  fh = io.open path, "rb"
  return nil, "Cannot open #{path}" unless fh
  data = fh\read "*a"
  fh\close!

  if path\match "%.bin$"
    -- Fichier binaire précompilé
    n = math.floor #data / 8
    return nil, "Empty bin file: #{path}" if n == 0
    arr = ffi.new "uint64_t[?]", n
    ffi.copy arr, data, n * 8
    return arr, n

  else
    -- Fichier texte : un domaine par ligne
    hashes = {}
    for line in data\gmatch "[^\n]+"
      domain = line\match "^%s*(.-)%s*$"
      domain = (domain\match "^([^#]*)") or ""
      domain = domain\match "^%s*(.-)%s*$"
      hashes[#hashes + 1] = xxhash.xxh64(domain) if domain ~= ""

    n = #hashes
    return nil, "Empty domains file: #{path}" if n == 0

    table.sort hashes, (a, b) -> a < b
    arr = ffi.new "uint64_t[?]", n
    for i = 1, n
      arr[i - 1] = hashes[i]
    return arr, n

--- Teste si un domaine (ou un suffixe) est dans le tableau trié.
-- Essaie d'abord le domaine exact, puis chaque suffixe de gauche à droite.
-- @tparam cdata   arr    Tableau FFI uint64_t[N] trié
-- @tparam number  n      Nombre d'entrées
-- @tparam string  domain Domaine à chercher
-- @treturn boolean, string
local lookup
lookup = (arr, n, domain) ->
  { :xxh64 }   = require "ffi_xxhash"
  { :bsearch } = require "filter.lib.bsearch"

  -- Exact
  return true if bsearch arr, n, xxh64(domain)

  -- Suffixes
  pos = domain\find ".", 1, true
  while pos
    suffix = domain\sub pos + 1
    return true if bsearch arr, n, xxh64(suffix)
    pos = domain\find ".", pos + 1, true

  false

--- @tparam table cfg Configuration du filtre ({domains: {name: path, ...}, ...})
-- @treturn function factory (listname: string) → (req) → bool, reason
(cfg) -> (listname) ->
  path = cfg.domains and cfg.domains[listname]
  unless path
    return (req) -> false, "Domain list '#{listname}' not defined in cfg"

  arr, n_or_err = load_list path
  unless arr
    msg = "Cannot load domain list '#{listname}': #{n_or_err}"
    return (req) -> false, msg

  n = n_or_err

  --- @tparam table req {domain: string, ...}
  -- @treturn boolean, string
  (req) ->
    domain = req.domain
    return false, "Missing domain in request" unless domain
    if lookup arr, n, domain
      true, "Domain matched in list '#{listname}'"
    else
      false, "Domain not in list '#{listname}'"
