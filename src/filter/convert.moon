#!/usr/bin/env moonjit
-- src/filter/convert.moon
-- Outil CLI : convertit un fichier texte de domaines en fichier binaire
-- trié (format .bin pour to_domainlist.moon).
--
-- Usage : luajit lua/filter/convert.lua <input.domains> <output.bin>
--
-- Format de sortie : N × 6 octets little-endian (xxh64 tronqué 48 bits),
-- trié, sans en-tête (cf. filter.lib.bin48). Les domaines en double sont
-- dédupliqués silencieusement.

bin48 = require "filter.lib.bin48"

-- ── Arguments ────────────────────────────────────────────────────
if #arg < 2
  io.stderr\write "Usage: luajit lua/filter/convert.lua <input.domains> <output.bin>\n"
  os.exit 1

input_path  = arg[1]
output_path = arg[2]

-- ── Lecture ────────────────────────────────────────────────────────
fh = io.open input_path, "r"
if not fh
  io.stderr\write "Impossible d'ouvrir : #{input_path}\n"
  os.exit 1

domains = {}
for line in fh\lines!
  domain = line\match "^%s*(.-)%s*$"        -- trim
  domain = domain\match "^([^#]*)" or ""    -- enlever commentaires inline
  domain = domain\match "^%s*(.-)%s*$"      -- trim à nouveau
  domains[#domains + 1] = domain if domain != ""

fh\close!

-- ── Hachage, tri, empaquetage 48 bits ─────────────────────────────
payload, n = bin48.pack_domains domains

if n == 0
  io.stderr\write "Aucun domaine valide dans #{input_path}\n"
  os.exit 1

-- ── Écriture ──────────────────────────────────────────────────────
out = io.open output_path, "wb"
if not out
  io.stderr\write "Impossible d'écrire : #{output_path}\n"
  os.exit 1

out\write payload
out\close!

io.stderr\write "#{n} domaines → #{output_path} (#{#payload} octets)\n"
