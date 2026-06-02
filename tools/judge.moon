#!/usr/bin/env moon
-- tools/judge.moon
-- Outil de diagnostic : indique sur quelles listes binaires custos un domaine
-- est présent, et si le match est exact ou via un suffixe parent.
--
-- Usage :
--   moon tools/judge.moon <bin-dir> <domain>
--
-- Exemple :
--   moon tools/judge.moon /etc/custos/lists/toulouse ads.example.com
--
-- Sortie (une ligne par match) :
--   <liste>   EXACT           (domaine présent tel quel)
--   <liste>   SUFFIX <parent> (suffix présent dans la liste)
-- Si aucun match, un message le dit et le code de sortie est 1.

ffi = require "ffi"

-- ── Ajout du lua/ du projet au package.path ──────────────────────────────
do
  script_dir = arg[0]\match("^(.*)/[^/]+$") or "."
  project_root = script_dir\match("^(.*)/tools$") or script_dir .. "/.."
  lua_dir = project_root .. "/lua"
  package.path = lua_dir .. "/?.lua;" .. lua_dir .. "/?/init.lua;" .. package.path

-- ── Argument parsing ──────────────────────────────────────────────────────

usage = ->
  io.stderr\write "Usage: moon tools/judge.moon <bin-dir> [<bin-dir> ...] <domain>\n"
  os.exit 2

domain  = arg[#arg]
bin_dirs = [arg[i] for i = 1, #arg - 1]

usage! unless #bin_dirs > 0 and domain and domain != ""

-- ── Helpers ───────────────────────────────────────────────────────────────

bin48   = require "filter.lib.bin48"
xxhash  = require "ffi_xxhash"

pcall -> ffi.cdef [[
  int open(const char *path, int oflag, ...);
  int close(int fd);
  long lseek(int fd, long offset, int whence);
  void *mmap(void *addr, size_t len, int prot, int flags, int fd, long offset);
  int munmap(void *addr, size_t len);
]]

O_RDONLY   = 0
SEEK_END   = 2
PROT_READ  = 0x1
MAP_SHARED = 0x01
MAP_FAILED = ffi.cast "void*", -1

--- Charge un fichier .bin et retourne (arr8, n, rec_size) ou (nil, err).
-- Détecte automatiquement le format : 6 octets (bin48) ou 8 octets (uint64).
load_bin = (path) ->
  fd = ffi.C.open path, O_RDONLY, 0
  return nil, "cannot open '#{path}'" if fd < 0
  size = tonumber ffi.C.lseek fd, 0, SEEK_END
  rec_size = 0
  rec_size = 6 if size > 0 and size % 6 == 0
  rec_size = 8 if size > 0 and size % 6 != 0 and size % 8 == 0
  if size == 0
    ffi.C.close fd
    return nil, nil  -- liste vide, on ignore silencieusement
  if rec_size == 0
    ffi.C.close fd
    return nil, "taille #{size} non multiple de 6 ou 8 pour '#{path}'"
  n = size / rec_size
  ptr = ffi.C.mmap nil, size, PROT_READ, MAP_SHARED, fd, 0
  ffi.C.close fd
  return nil, "mmap failed for '#{path}'" if ptr == MAP_FAILED
  arr = ffi.cast "const uint8_t*", ptr
  arr, n, rec_size

-- Recherche binaire pour le format uint64 (8 octets, little-endian).
bsearch_u64 = (arr8, n, target) ->
  TWO32 = 0x100000000ULL
  _u32  = ffi.typeof "const uint32_t*"
  lo, hi = 0, n - 1
  while lo <= hi
    mid = math.floor (lo + hi) * 0.5
    b   = arr8 + mid * 8
    v   = ffi.cast("uint64_t", (ffi.cast _u32, b)[0]) +
          ffi.cast("uint64_t", (ffi.cast _u32, b + 4)[0]) * TWO32
    if v == target then return true
    elseif v < target then lo = mid + 1
    else hi = mid - 1
  false

--- Cherche le domaine exact ou via ses suffixes dans (arr, n, rec_size).
-- Retourne "exact", ou "suffix:<matched_part>", ou nil.
check = (arr, n, rec_size, dom) ->
  bsearch_fn = rec_size == 6 and
    ((a, nn, h) -> bin48.bsearch a, nn, bin48.truncate h) or
    ((a, nn, h) -> bsearch_u64 a, nn, h)

  h = xxhash.xxh64 dom
  return "exact" if bsearch_fn arr, n, h

  pos = dom\find ".", 1, true
  while pos
    suffix = dom\sub pos + 1
    h = xxhash.xxh64 suffix
    if bsearch_fn arr, n, h
      return "suffix:#{suffix}"
    pos = dom\find ".", pos + 1, true

  nil

-- ── Découverte des .bin ───────────────────────────────────────────────────

-- { path, label } — label = "liste" ou "dossier/liste" si plusieurs dossiers
bin_entries = {}
multi_dir   = #bin_dirs > 1

for dir in *bin_dirs
  pipe = io.popen "ls -1 " .. dir .. "/*.bin 2>/dev/null"
  if pipe
    for path in pipe\lines!
      name  = path\match "([^/]+)%.bin$"
      label = multi_dir and (dir\gsub "/*$", "") .. "/" .. name or name
      bin_entries[#bin_entries + 1] = { :path, :label }
    pipe\close!

if #bin_entries == 0
  io.stderr\write "Aucun fichier .bin trouvé\n"
  os.exit 2

-- ── Recherche sur toutes les listes ──────────────────────────────────────

exact_lists  = {}
suffix_lists = {}  -- { [parent]: { labels... } }

for { :path, :label } in *bin_entries
  arr, n, rec_size = load_bin path
  unless arr
    io.stderr\write "[warn] #{n}\n" if n  -- nil = liste vide, pas de warning
    continue

  result = check arr, n, rec_size, domain
  if result == "exact"
    exact_lists[#exact_lists + 1] = label
  elseif result
    parent = result\sub 8  -- retire "suffix:"
    suffix_lists[parent] or= {}
    t = suffix_lists[parent]
    t[#t + 1] = label

-- ── Affichage ─────────────────────────────────────────────────────────────

found_any = #exact_lists > 0 or next(suffix_lists) != nil

unless found_any
  io.stderr\write "#{domain} : aucun match dans #{table.concat bin_dirs, ", "}\n"
  os.exit 1

if #exact_lists > 0
  table.sort exact_lists
  print "Exact (#{domain}) : #{table.concat exact_lists, ", "}"

-- Tri des parents par longueur décroissante (le plus spécifique d'abord)
parents = [p for p in pairs suffix_lists]
table.sort parents, (a, b) -> #a > #b
for parent in *parents
  names = suffix_lists[parent]
  table.sort names
  print "Suffixe (#{parent}) : #{table.concat names, ", "}"
