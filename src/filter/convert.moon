#!/usr/bin/env moonjit
-- src/filter/convert.moon
-- Outil CLI : convertit un fichier texte de domaines en tableau binaire
-- uint64_t trié (format .bin pour to_domainlist.moon).
--
-- Usage : luajit lua/filter/convert.lua <input.domains> <output.bin>
--
-- Format de sortie : N × 8 octets little-endian uint64_t, sans en-tête.
-- Chaque domaine est haché avec XXH64 (seed=0). Les hashes sont triés.
--
-- Les domaines en double (collisions de chaîne ou de hash) sont dédupliqués
-- silencieusement.

ffi    = require "ffi"
xxhash = require "ffi_xxhash"

ffi.cdef [[
  void qsort(void* base, size_t n, size_t size, int (*cmp)(const void*, const void*));
]]

-- ── Arguments ────────────────────────────────────────────────────
if #arg < 2
  io.stderr\write "Usage: luajit lua/filter/convert.lua <input.domains> <output.bin>\n"
  os.exit 1

input_path  = arg[1]
output_path = arg[2]

-- ── Lecture et hachage ────────────────────────────────────────────
fh = io.open input_path, "r"
if not fh
  io.stderr\write "Impossible d'ouvrir : #{input_path}\n"
  os.exit 1

hashes = {}
seen   = {}
n      = 0

for line in fh\lines!
  domain = line\match "^%s*(.-)%s*$"        -- trim
  domain = domain\match "^([^#]*)" or ""    -- enlever commentaires inline
  domain = domain\match "^%s*(.-)%s*$"      -- trim à nouveau
  continue if domain == ""
  continue if seen[domain]
  seen[domain] = true
  h = xxhash.xxh64 domain
  n += 1
  hashes[n] = h

fh\close!

if n == 0
  io.stderr\write "Aucun domaine valide dans #{input_path}\n"
  os.exit 1

-- ── Tri ───────────────────────────────────────────────────────────
-- Trie un tableau Lua de cdata uint64_t. LuaJIT supporte < sur les cdata.
table.sort hashes, (a, b) -> a < b

-- Copie dans un tableau FFI
arr = ffi.new "uint64_t[?]", n
for i = 1, n
  arr[i - 1] = hashes[i]

-- ── Écriture ──────────────────────────────────────────────────────
out = io.open output_path, "wb"
if not out
  io.stderr\write "Impossible d'écrire : #{output_path}\n"
  os.exit 1

out\write ffi.string arr, n * 8
out\close!

io.stderr\write "#{n} domaines → #{output_path} (#{n * 8} octets)\n"
