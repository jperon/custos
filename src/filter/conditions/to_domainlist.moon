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
{ :libc } = require "ffi_defs"

-- ── Constantes mmap (lecture seule partagée des .bin) ─────────────────
PROT_READ  = 0x1
MAP_SHARED = 0x01
O_RDONLY   = 0
SEEK_END   = 2
MAP_FAILED = ffi.cast "void*", -1

-- Conserve une référence sur chaque mapping pour la durée du process :
-- ffi.gc(ptr, munmap) ne se déclenche qu'au GC du cdata. Tant que le tableau
-- de conditions capture `arr` (pointeur casté), le mapping reste vivant ;
-- cette table sert d'ancrage de secours.
_mappings = {}

-- ── Cache LRU pour domaines fréquents ─────────────────────────────────
-- Évite de re-hasher et re-bsearch les domaines déjà vus récemment.
-- Capacité: 1000 entrées, TTL: 5 secondes
CACHE_MAX_SIZE  = 1000
CACHE_TTL_SEC   = 5
_domain_cache   = {}  -- { domain → { found: bool, ts: epoch } }
_domain_cache_order = {}  -- Liste pour LRU (plus vieux en premier)
_cache_hits     = 0
_cache_misses   = 0

--- Retourne les stats du cache (hits, misses).
get_cache_stats = -> { hits: _cache_hits, misses: _cache_misses }

--- Vide le cache (utile pour tests).
clear_cache = ->
  _domain_cache = {}
  _domain_cache_order = {}
  _cache_hits = 0
  _cache_misses = 0

--- Maintient le cache LRU sous la taille max.
_evict_oldest_if_needed = ->
  while #_domain_cache_order >= CACHE_MAX_SIZE
    oldest = table.remove _domain_cache_order, 1
    _domain_cache[oldest] = nil if oldest

--- Charge une liste de domaines depuis un fichier .bin ou .domains.
-- @tparam string path Chemin vers le fichier
-- @treturn cdata, number Tableau uint64_t[] et nombre d'entrées, ou nil, msg
local load_list
load_list = (path) ->
  xxhash_ok, xxhash = pcall require, "ffi_xxhash"
  return nil, "ffi_xxhash non disponible" unless xxhash_ok
  bsearch_m = require "filter.lib.bsearch"

  if path\match "%.bin$"
    -- Fichier binaire précompilé : mappé en lecture seule partagée (MAP_SHARED).
    -- Aucune recopie : le pointeur FFI pointe directement sur la page (tmpfs),
    -- partagée entre tous les workers forkés (lecture seule → jamais dupliquée).
    fd = libc.open path, O_RDONLY, 0
    return nil, "Cannot open #{path}" if fd < 0
    size = tonumber libc.lseek fd, 0, SEEK_END
    if size <= 0
      libc.close fd
      return nil, "Empty bin file: #{path}"
    n = math.floor size / 8
    if n == 0
      libc.close fd
      return nil, "Empty bin file: #{path}"
    ptr = libc.mmap nil, size, PROT_READ, MAP_SHARED, fd, 0
    libc.close fd  -- le mapping survit au close
    if ptr == MAP_FAILED
      return nil, "mmap failed: #{path}"
    ffi.gc ptr, (p) -> libc.munmap p, size
    _mappings[#_mappings + 1] = ptr
    arr = ffi.cast "uint64_t*", ptr
    return arr, n

  else
    -- Fichier texte : un domaine par ligne
    fh = io.open path, "rb"
    return nil, "Cannot open #{path}" unless fh
    data = fh\read "*a"
    fh\close!
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

--- Teste si un domaine (ou un suffixe) est dans le tableau trié avec cache LRU.
-- Essaie d'abord le domaine exact, puis chaque suffixe de gauche à droite.
-- @tparam cdata   arr    Tableau FFI uint64_t[N] trié
-- @tparam number  n      Nombre d'entrées
-- @tparam string  domain Domaine à chercher
-- @tparam string  listname Identifiant de liste pour la clé de cache (optional)
-- @treturn boolean, string
local lookup
lookup = (arr, n, domain, listname) ->
  { :xxh64 }   = require "ffi_xxhash"
  { :bsearch } = require "filter.lib.bsearch"

  now = os.time!
  -- Clé de cache composite: "listname:domain" ou juste "domain" si pas de listname
  cache_key = listname and "#{listname}:#{domain}" or domain

  -- Vérifier le cache d'abord
  cached = _domain_cache[cache_key]
  if cached
    if now - cached.ts < CACHE_TTL_SEC
      _cache_hits += 1
      return cached.found
    else
      -- Expiré: retirer
      _domain_cache[cache_key] = nil
      for i, d in ipairs _domain_cache_order
        if d == cache_key
          table.remove _domain_cache_order, i
          break

  _cache_misses += 1

  -- Exact
  found = bsearch arr, n, xxh64(domain)

  -- Suffixes (si pas trouvé exact)
  if not found
    pos = domain\find ".", 1, true
    while pos
      suffix = domain\sub pos + 1
      if bsearch arr, n, xxh64(suffix)
        found = true
        break
      pos = domain\find ".", pos + 1, true

  -- Stocker dans le cache
  _evict_oldest_if_needed!
  _domain_cache[cache_key] = { found: found, ts: now }
  _domain_cache_order[#_domain_cache_order + 1] = cache_key

  found

--- @tparam table cfg Configuration
-- @treturn function factory (listname) → enriched_condition

_schema = {
  label:       "Liste de domaines"
  description: "Domaine présent dans une liste compilée (.bin/.domains)"
  category:    "destination"
  arg_type:    "string"
  arg_hint:    "ex: toulouse/malware"
}

_factory = (cfg) ->
  (listname) ->
    unless cfg.domainlists_dir
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "domainlists_dir non défini"
      }
    
    -- Validation du nom de liste
    if listname\match "^/" or listname\match "%.%." or listname\match "%.bin$"
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "Nom de liste invalide: '#{listname}'"
      }
    
    base = (cfg.domainlists_dir\gsub "/*$", "") .. "/" .. listname
    path = base .. ".bin"

    arr, n_or_err = load_list path
    -- Fallback : si le .bin est absent, essayer un fichier texte (.domains)
    unless arr
      arr, n_or_err = load_list base .. ".domains"
    unless arr
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "Cannot load domain list '#{listname}': #{n_or_err}"
      }

    n = n_or_err

    {
      capabilities: { worker: true, nft: false, nft_dynamic: false }
      listname: listname
      eval: (req) ->
        domain = req.domain
        return false, "Missing domain in request" unless domain
        if lookup arr, n, domain, listname
          true, "Domain matched in list '#{listname}'"
        else
          false, "Domain not in list '#{listname}'"
      creates_dynamic_scope: true
    }

{ schema: _schema, factory: _factory }
