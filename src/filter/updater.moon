#!/usr/bin/env moonjit
-- src/filter/updater.moon
-- Outil CLI : télécharge et compile les listes de domaines vers des fichiers .bin.
--
-- Usage : luajit lua/filter/updater.lua [--config path] [--pid path] [--dry-run]
--
-- Lit la section cfg.sources de la configuration du filtre :
--   sources:
--     nom_liste:
--       urls:   { "https://...", ... }   -- une ou plusieurs URLs (fusionnées)
--       format: "simple"|"hosts"|"adblock"
--       output: "/chemin/vers/liste.bin"
--
-- Formats supportés (voir filter/lib/parse_domains.moon) :
--   simple  : un domaine par ligne, # pour les commentaires
--   hosts   : 0.0.0.0 domain.com (format /etc/hosts)
--   adblock : ||domain.com^ (format uBlock/AdBlock)
--
-- Pour chaque source :
--   1. Télécharge chaque URL via curl
--   2. Parse les domaines selon le format
--   3. Fusionne et déduplique
--   4. Hash xxh64 + tri + écriture atomique (.tmp → rename)
-- Si --pid est fourni et qu'au moins une liste a été mise à jour,
-- envoie SIGHUP au daemon.

ffi          = require "ffi"
xxhash       = require "ffi_xxhash"
parse_domains = require "filter.lib.parse_domains"
{ :load_config } = require "filter.lib.load_config"

ffi.cdef [[
  int rename(const char *oldpath, const char *newpath);
  int kill(int pid, int sig);
]]

SIGHUP = 1

-- ── Analyse des arguments ─────────────────────────────────────────

--- Parse les arguments de la ligne de commande.
-- @tparam table argv  Table arg de Lua (arg[1], arg[2], …)
-- @treturn table      Options : { config, pid_file, dry_run }
parse_args = (argv) ->
  opts = { dry_run: false }
  i = 1
  while argv[i]
    switch argv[i]
      when "--config"
        i += 1
        opts.config = argv[i]
      when "--pid"
        i += 1
        opts.pid_file = argv[i]
      when "--dry-run"
        opts.dry_run = true
    i += 1
  opts

-- ── Téléchargement ────────────────────────────────────────────────

--- Télécharge une URL via curl et retourne le contenu.
-- Utilise curl avec un timeout de 30 s et --fail pour détecter les erreurs HTTP.
-- @tparam  string      url URL à télécharger
-- @treturn string|nil  Contenu, ou nil en cas d'erreur
-- @treturn nil|string  Message d'erreur
download = (url) ->
  cmd = "curl --silent --location --max-time 30 --fail " .. url
  fh = io.popen cmd
  return nil, "popen failed" unless fh
  data = fh\read "*a"
  ok = fh\close!
  return nil, "curl failed (HTTP error ou timeout) : #{url}" unless ok and #data > 0
  data, nil

-- ── Hash, tri et écriture atomique ────────────────────────────────

--- Hash, trie et écrit un ensemble de domaines dans un fichier .bin.
-- Le fichier est écrit de façon atomique via un fichier temporaire.
-- @tparam  table   domains     Tableau de chaînes de domaines
-- @tparam  string  output_path Chemin du fichier .bin de destination
-- @tparam  boolean dry_run     Si vrai, n'écrit pas
-- @treturn boolean             Succès
-- @treturn string              Message (nb domaines ou erreur)
write_bin = (domains, output_path, dry_run) ->
  seen, hashes, n = {}, {}, 0
  for domain in *domains
    continue if seen[domain]
    seen[domain] = true
    n += 1
    hashes[n] = xxhash.xxh64 domain

  if n == 0
    return false, "aucun domaine valide"

  table.sort hashes, (a, b) -> a < b

  arr = ffi.new "uint64_t[?]", n
  for i = 1, n
    arr[i - 1] = hashes[i]

  if dry_run
    return true, "dry-run : #{n} domaines → #{output_path}"

  tmp = output_path .. ".tmp"
  fh = io.open tmp, "wb"
  return false, "impossible d'écrire #{tmp}" unless fh
  fh\write ffi.string arr, n * 8
  fh\close!

  ret = ffi.C.rename tmp, output_path
  if ret ~= 0
    os.remove tmp
    return false, "rename échoué : #{tmp} → #{output_path}"

  true, "#{n} domaines → #{output_path} (#{n * 8} octets)"

-- ── Programme principal ───────────────────────────────────────────

opts = parse_args arg

cfg_path = opts.config or "cfg/filter.yml"
cfg, err = load_config cfg_path
unless cfg
  io.stderr\write "Erreur de chargement de la config #{cfg_path} : #{err}\n"
  os.exit 1

sources = cfg.sources or {}
if next(sources) == nil
  io.stderr\write "Aucune source définie dans cfg.sources — rien à faire.\n"
  os.exit 0

updated = 0
errors  = 0

for name, source in pairs sources
  urls   = source.urls or {}
  format = source.format or "simple"
  output = source.output

  unless output
    io.stderr\write "[#{name}] SKIP : pas de chemin output défini\n"
    errors += 1
    continue

  if #urls == 0
    io.stderr\write "[#{name}] SKIP : aucune URL définie\n"
    errors += 1
    continue

  -- Téléchargement et fusion de toutes les URLs de cette source
  all_domains = {}
  failed      = false

  for url in *urls
    io.stderr\write "[#{name}] GET #{url} ... "
    data, err = download url
    if err
      io.stderr\write "ERREUR : #{err}\n"
      failed = true
      break
    domains = parse_domains.parse format, data
    io.stderr\write "#{#domains} domaines\n"
    for d in *domains
      all_domains[#all_domains + 1] = d

  if failed
    io.stderr\write "[#{name}] Source ignorée (erreur de téléchargement)\n"
    errors += 1
    continue

  io.stderr\write "[#{name}] #{#all_domains} domaines total → #{output}\n"
  ok, msg = write_bin all_domains, output, opts.dry_run
  if ok
    io.stderr\write "[#{name}] ✓ #{msg}\n"
    updated += 1
  else
    io.stderr\write "[#{name}] ✗ #{msg}\n"
    errors += 1

-- Envoi du SIGHUP si demandé et si au moins une liste a été mise à jour
if opts.pid_file and updated > 0 and not opts.dry_run
  fh = io.open opts.pid_file, "r"
  if fh
    pid_str = fh\read "*l"
    fh\close!
    pid = tonumber pid_str
    if pid and pid > 0
      ret = ffi.C.kill pid, SIGHUP
      if ret == 0
        io.stderr\write "SIGHUP envoyé au PID #{pid}\n"
      else
        io.stderr\write "Échec de l'envoi du SIGHUP au PID #{pid}\n"
    else
      io.stderr\write "PID invalide dans #{opts.pid_file}\n"
  else
    io.stderr\write "Impossible de lire #{opts.pid_file}\n"

io.stderr\write "Terminé : #{updated} liste(s) mise(s) à jour, #{errors} erreur(s).\n"
os.exit errors > 0 and 1 or 0
