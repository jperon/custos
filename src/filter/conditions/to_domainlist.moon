-- src/filter/conditions/to_domainlist.moon
-- Condition : le domaine demandé (ou un suffixe) se trouve dans une liste
-- de domaines précompilée.
--
-- Contrairement à shelterfilter :
--   • Pas de fork : la DB est chargée en mémoire dans le même processus.
--   • Pas de tonumber() : arithmétique cdata → précision totale.
--   • Format .bin : N × 6 octets (xxh64 tronqué 48 bits) little-endian trié,
--     sans en-tête (cf. filter.lib.bin48 ; −25 % de RAM vs uint64).
--   • Format .domains (texte, un domaine par ligne) : chargé, haché et
--     empaqueté à la volée au démarrage (utile en développement).

ffi  = require "ffi"
{ :libc } = require "ffi_defs"

-- Modules hot-path mémoïsés (évite un require par lookup) : bin48
-- (bsearch/truncate) et xxhash (hachage). On les résout une seule fois, à la
-- CONSTRUCTION de la condition (via load_list, au démarrage), pas au require du
-- module — charger ffi_xxhash au require perturberait l'ordre d'initialisation
-- FFI global. Per-paquet, l'accès se fait par upvalue (coût nul).
bin48  = nil
_xxh64 = nil

-- Résout et mémoïse bin48 + xxh64. Idempotent. Retourne false si ffi_xxhash est
-- indisponible (load_list échoue alors, et aucune condition n'est construite →
-- lookup n'est jamais atteint sans _xxh64).
_ensure_libs = ->
  return true if bin48 and _xxh64
  ok, xxhash = pcall require, "ffi_xxhash"
  return false unless ok
  bin48  = require "filter.lib.bin48"
  _xxh64 = xxhash.xxh64
  true

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

-- ── Cache pour domaines fréquents ─────────────────────────────────────
-- Évite de re-hasher et re-bsearch les domaines déjà vus récemment.
-- Capacité ~1000 entrées, TTL 5 secondes.
--
-- Structure à deux niveaux { listname → { domain → {found, ts} } } : évite la
-- concaténation d'une clé composite "listname:domain" à chaque appel (le
-- listname est fixe par condition). Éviction générationnelle paresseuse : quand
-- le nombre total d'entrées dépasse la capacité, on en jette ~la moitié en une
-- passe — coût amorti O(1) par insertion, contre l'ancien `table.remove(ordre,1)`
-- qui décalait ~1000 éléments à chaque éviction (≈10× plus lent sous churn).
CACHE_MAX_SIZE  = 1000
CACHE_TTL_SEC   = 5
_domain_cache   = {}  -- { listname → { domain → { found: bool, ts: epoch } } }
_cache_count    = 0   -- nombre total d'entrées (toutes listes confondues)
_cache_hits     = 0
_cache_misses   = 0

-- Clé de sous-table pour un listname nil (lookup sans liste nommée).
_NIL_LIST = "\0"

--- Retourne les stats du cache (hits, misses).
get_cache_stats = -> { hits: _cache_hits, misses: _cache_misses }

--- Vide le cache (utile pour tests).
clear_cache = ->
  _domain_cache = {}
  _cache_count  = 0
  _cache_hits   = 0
  _cache_misses = 0

--- Maintient le cache sous la taille max (éviction générationnelle amortie).
-- Jette ~la moitié des entrées les plus anciennes en termes d'ordre d'itération.
_evict_if_needed = ->
  return if _cache_count <= CACHE_MAX_SIZE
  target = math.floor CACHE_MAX_SIZE / 2
  kept = 0
  for _, sub in pairs _domain_cache
    for d in pairs sub
      if kept >= target
        sub[d] = nil
      else
        kept += 1
  _cache_count = kept

--- Charge une liste de domaines depuis un fichier .bin ou .domains.
-- @tparam string path Chemin vers le fichier
-- @treturn cdata, number Pointeur uint8_t* (enregistrements 6 octets) et
--   nombre d'entrées, ou nil, msg
local load_list
load_list = (path) ->
  return nil, "ffi_xxhash non disponible" unless _ensure_libs!

  if path\match "%.bin$"
    -- Fichier binaire précompilé : mappé en lecture seule partagée (MAP_SHARED).
    -- Aucune recopie : le pointeur FFI pointe directement sur la page (tmpfs),
    -- partagée entre tous les workers forkés (lecture seule → jamais dupliquée).
    -- Format : N × 6 octets (xxh64 tronqué 48 bits), little-endian, trié.
    fd = libc.open path, O_RDONLY, 0
    return nil, "Cannot open #{path}" if fd < 0
    size = tonumber libc.lseek fd, 0, SEEK_END
    if size <= 0
      libc.close fd
      return nil, "Empty bin file: #{path}"
    n = math.floor size / 6
    if n == 0
      libc.close fd
      return nil, "Empty bin file: #{path}"
    ptr = libc.mmap nil, size, PROT_READ, MAP_SHARED, fd, 0
    libc.close fd  -- le mapping survit au close
    if ptr == MAP_FAILED
      return nil, "mmap failed: #{path}"
    ffi.gc ptr, (p) -> libc.munmap p, size
    _mappings[#_mappings + 1] = ptr
    arr = ffi.cast "const uint8_t*", ptr
    return arr, n

  else
    -- Fichier texte : un domaine par ligne, empaqueté en mémoire au format 48 bits.
    fh = io.open path, "rb"
    return nil, "Cannot open #{path}" unless fh
    data = fh\read "*a"
    fh\close!
    domains = {}
    for line in data\gmatch "[^\n]+"
      domain = line\match "^%s*(.-)%s*$"
      domain = (domain\match "^([^#]*)") or ""
      domain = domain\match "^%s*(.-)%s*$"
      domains[#domains + 1] = domain if domain ~= ""

    payload, n = bin48.pack_domains domains
    return nil, "Empty domains file: #{path}" if n == 0

    -- Conserver le buffer vivant pour la durée du process (comme les mappings).
    _mappings[#_mappings + 1] = payload
    arr = ffi.cast "const uint8_t*", payload
    return arr, n

--- Teste si un domaine (ou un suffixe) est dans le tableau trié avec cache LRU.
-- Essaie d'abord le domaine exact, puis chaque suffixe de gauche à droite.
-- @tparam cdata   arr    Pointeur uint8_t* (enregistrements 6 octets triés)
-- @tparam number  n      Nombre d'entrées
-- @tparam string  domain Domaine à chercher
-- @tparam string  listname Identifiant de liste pour la clé de cache (optional)
-- @treturn boolean, string
local lookup
lookup = (arr, n, domain, listname) ->
  now = os.time!
  lkey = listname or _NIL_LIST
  sub = _domain_cache[lkey]
  unless sub
    sub = {}
    _domain_cache[lkey] = sub

  -- Vérifier le cache d'abord (lookup direct à deux niveaux, sans concat)
  cached = sub[domain]
  if cached and now - cached.ts < CACHE_TTL_SEC
    _cache_hits += 1
    return cached.found

  _cache_misses += 1

  -- Exact
  found = bin48.bsearch arr, n, bin48.truncate _xxh64 domain

  -- Suffixes (si pas trouvé exact)
  if not found
    pos = domain\find ".", 1, true
    while pos
      suffix = domain\sub pos + 1
      if bin48.bsearch arr, n, bin48.truncate _xxh64 suffix
        found = true
        break
      pos = domain\find ".", pos + 1, true

  -- Stocker dans le cache. Nouvelle clé → incrémente le compteur puis évince si
  -- nécessaire ; clé existante (entrée expirée) → réécriture en place.
  -- _evict_if_needed vide des entrées mais ne supprime jamais la sous-table
  -- elle-même, donc `sub` reste valide après l'appel.
  unless cached
    _cache_count += 1
    _evict_if_needed!
  sub[domain] = { found: found, ts: now }

  found

--- @tparam table cfg Configuration
-- @treturn function factory (listname) → enriched_condition

_schema = {
  label:       "Liste de domaines"
  description: "Domaine présent dans une liste compilée (.bin/.domains)"
  category:    "destination"
  arg_type:    "string"
  arg_hint:    "ex: toulouse/malware"
  -- Libellés/hints spécifiques des variantes auto-générées (lus par
  -- webui.schema.registry). La variante `_list` (to_domainlist_list) lit un
  -- fichier nommé dont chaque ligne est un nom de domainlist : c'est un
  -- « groupe de domainlists » réutilisable entre règles.
  forms: {
    list:  {
      label:       "Groupe de listes (fichier nommé)"
      hint:        "nom d'un fichier listant des domainlists, une par ligne"
      description: "Domaine présent dans l'une des domainlists nommées dans ce fichier-groupe"
    }
    lists: {
      label: "Plusieurs groupes de listes"
      hint:  "un nom de fichier-groupe par ligne"
    }
  }
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
