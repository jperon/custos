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
--   # Format Toulouse (tar.gz DSI UT Capitole) :
--     nom_liste:
--       url:        "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"
--       format:     toulouse
--       categories: [ads, malware, phishing, ...]   -- optionnel, toutes si absent
--       output:     "/chemin/vers/liste.bin"
--
-- Formats supportés (voir filter/lib/parse_domains.moon) :
--   simple   : un domaine par ligne, # pour les commentaires
--   hosts    : 0.0.0.0 domain.com (format /etc/hosts)
--   adblock  : ||domain.com^ (format uBlock/AdBlock)
--   toulouse : tar.gz DSI UT Capitole (blacklists/<cat>/domains)
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

--- Télécharge une URL vers un fichier local.
-- @tparam  string   url      URL à télécharger
-- @tparam  string   dest     Chemin de destination
-- @tparam  number   timeout  Timeout en secondes
-- @treturn boolean           Succès
download_file = (url, dest, timeout) ->
  timeout = timeout or 120
  cmd = "curl --silent --location --max-time #{timeout} --fail -o #{dest} #{url}"
  ret = os.execute cmd
  ret == 0

-- ── Format Toulouse ───────────────────────────────────────────────

--- Télécharge et parse une source au format Toulouse (DSI UT Capitole).
-- Le fichier tar.gz contient des sous-dossiers par catégorie :
--   blacklists/<categorie>/domains  (une ligne = un domaine)
--
-- Deux modes de sortie (mutuellement exclusifs) :
--   output     : fusionne toutes les catégories en un seul fichier .bin
--   output_dir : crée un fichier <output_dir>/<categorie>.bin par catégorie
--
-- Si source.categories est absent ou vide, toutes les catégories sont extraites.
-- @tparam  string   name       Nom de la source (pour les logs)
-- @tparam  table    source     { url, categories, output|output_dir }
-- @tparam  boolean  dry_run
-- @treturn boolean             Succès
-- @treturn string              Message (nb domaines ou erreur)
fetch_toulouse = (name, source, dry_run) ->
  url         = source.url
  cats_filter = source.categories  -- table|nil
  output      = source.output      -- chemin unique (fusion)
  output_dir  = source.output_dir  -- répertoire (un .bin par catégorie)

  return false, "pas d'URL définie" unless url
  unless output or output_dir
    return false, "pas de chemin output ou output_dir défini"

  -- Fichier temporaire pour le tar.gz
  tmp_base = output_dir and ((output_dir\gsub "/*$", "") .. "/toulouse") or output
  tmp_tar  = tmp_base .. ".tar.gz.tmp"

  -- Téléchargement
  io.stderr\write "[#{name}] GET #{url} ... "
  unless download_file url, tmp_tar
    os.remove tmp_tar
    return false, "curl échoué (HTTP error ou timeout)"
  io.stderr\write "OK\n"

  -- Lister toutes les catégories disponibles dans le tar
  fh = io.popen "tar -tzf #{tmp_tar} 2>/dev/null"
  all_cats = {}
  if fh
    for line in fh\lines!
      cat = line\match "^blacklists/([^/]+)/domains$"
      all_cats[#all_cats + 1] = cat if cat
    fh\close!

  -- Filtrer si une sélection est demandée
  cats = if cats_filter and #cats_filter > 0
    wanted = {}
    wanted[c] = true for c in *cats_filter
    [c for c in *all_cats when wanted[c]]
  else
    all_cats

  if #cats == 0
    os.remove tmp_tar
    return false, "aucune catégorie trouvée dans le tar"

  io.stderr\write "[#{name}] #{#cats} catégorie(s)\n"

  -- Mode output_dir : un .bin par catégorie
  if output_dir
    base = output_dir\gsub "/*$", ""
    os.execute "mkdir -p #{base}"
    ok_count, err_count = 0, 0
    for cat in *cats
      fh = io.popen "tar -xzf #{tmp_tar} -O blacklists/#{cat}/domains 2>/dev/null"
      domains = {}
      if fh
        data = fh\read "*a"
        fh\close!
        domains = parse_domains.parse "simple", data
      cat_path = base .. "/" .. cat .. ".bin"
      ok, msg = write_bin domains, cat_path, dry_run
      if ok
        io.stderr\write "[#{name}/#{cat}] ✓ #{msg}\n"
        ok_count += 1
      else
        io.stderr\write "[#{name}/#{cat}] ✗ #{msg}\n"
        err_count += 1
    os.remove tmp_tar
    if err_count == 0
      return true, "#{ok_count} catégorie(s) → #{base}/"
    return err_count < ok_count, "#{ok_count} ok, #{err_count} erreur(s)"

  -- Mode output : fusion de toutes les catégories en un seul .bin
  all_domains = {}
  for cat in *cats
    fh = io.popen "tar -xzf #{tmp_tar} -O blacklists/#{cat}/domains 2>/dev/null"
    if fh
      data = fh\read "*a"
      fh\close!
      domains = parse_domains.parse "simple", data
      for d in *domains
        all_domains[#all_domains + 1] = d

  os.remove tmp_tar
  io.stderr\write "[#{name}] #{#all_domains} domaines total\n"
  write_bin all_domains, output, dry_run

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

-- ── Listes personnalisées (fichier local) ────────────────────────

--- Traite une source dont le contenu est un fichier texte local.
-- Le fichier original est conservé ; un fichier .bin est écrit à côté ou
-- à l'emplacement indiqué par source.output.
-- @tparam  string   name       Nom de la source (pour les logs)
-- @tparam  table    source     { file, format, output }
-- @tparam  boolean  dry_run
-- @treturn boolean             Succès
-- @treturn string              Message
fetch_local = (name, source, dry_run) ->
  path   = source.file
  format = source.format or "simple"
  output = source.output or (path\gsub "%.%w+$", ".bin")

  fh = io.open path, "r"
  unless fh
    return false, "impossible de lire #{path}"
  data = fh\read "*a"
  fh\close!

  domains = parse_domains.parse format, data
  io.stderr\write "[#{name}] #{#domains} domaines depuis #{path}\n"
  write_bin domains, output, dry_run

--- Parcourt un répertoire et compile tous les fichiers .txt en .bin.
-- Les fichiers .txt originaux sont conservés.
-- @tparam  string   dir      Répertoire à scanner
-- @tparam  boolean  dry_run
-- @treturn number            Nombre de listes mises à jour
-- @treturn number            Nombre d'erreurs
process_custom_dir = (dir, dry_run) ->
  local_updated, local_errors = 0, 0
  fh = io.popen "ls -1 #{dir}/*.txt 2>/dev/null"
  unless fh
    return 0, 0
  for txt_path in fh\lines!
    txt_path = txt_path\gsub "%s+$", ""
    continue if txt_path == ""
    name = txt_path\match "([^/]+)%.txt$" or txt_path
    bin_path = txt_path\gsub "%.txt$", ".bin"
    ok_l, msg = fetch_local name, { file: txt_path, format: "simple", output: bin_path }, dry_run
    if ok_l
      io.stderr\write "[custom/#{name}] ✓ #{msg}\n"
      local_updated += 1
    else
      io.stderr\write "[custom/#{name}] ✗ #{msg}\n"
      local_errors += 1
  fh\close!
  local_updated, local_errors

-- ── Programme principal ───────────────────────────────────────────

opts = parse_args arg

cfg_path = opts.config or "cfg/filter.yml"
cfg, err = load_config cfg_path
unless cfg
  io.stderr\write "Erreur de chargement de la config #{cfg_path} : #{err}\n"
  os.exit 1

sources         = cfg.sources or {}
domainlists_dir = cfg.domainlists_dir
custom_lists_dir = cfg.custom_lists_dir

updated = 0
errors  = 0

for name, source in pairs sources
  format = source.format or "simple"

  -- Résolution du chemin de sortie :
  --   source.subdir → output_dir = <domainlists_dir>/<subdir>   (nouveau)
  --   source.output_dir           → utilisé tel quel              (compat)
  --   source.output               → chemin unique (fusion)        (compat)
  if source.subdir and not source.output_dir
    unless domainlists_dir
      io.stderr\write "[#{name}] SKIP : subdir défini mais domainlists_dir absent\n"
      errors += 1
      continue
    source = {k, v for k, v in pairs source}  -- shallow copy
    source.output_dir = (domainlists_dir\gsub "/*$", "") .. "/" .. source.subdir

  output = source.output

  -- Format Toulouse : traitement spécial (tar.gz multi-catégories)
  if format == "toulouse"
    ok, msg = fetch_toulouse name, source, opts.dry_run
    if ok
      io.stderr\write "[#{name}] ✓ #{msg}\n"
      updated += 1
    else
      io.stderr\write "[#{name}] ✗ #{msg}\n"
      errors += 1
    continue

  -- Source locale (file:) : lecture directe sans téléchargement
  if source.file
    ok, msg = fetch_local name, source, opts.dry_run
    if ok
      io.stderr\write "[#{name}] ✓ #{msg}\n"
      updated += 1
    else
      io.stderr\write "[#{name}] ✗ #{msg}\n"
      errors += 1
    continue

  -- Formats classiques : simple / hosts / adblock
  unless output
    io.stderr\write "[#{name}] SKIP : pas de chemin output défini\n"
    errors += 1
    continue

  -- Formats classiques : simple / hosts / adblock
  urls = source.urls or {}

  if #urls == 0
    io.stderr\write "[#{name}] SKIP : aucune URL définie ni fichier local (file:)\n"
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

-- Listes personnalisées (custom_lists_dir : scan automatique)
if custom_lists_dir
  io.stderr\write "\n[custom] Scan de #{custom_lists_dir}/*.txt\n"
  n_ok, n_err = process_custom_dir custom_lists_dir, opts.dry_run
  updated += n_ok
  errors  += n_err
  io.stderr\write "[custom] #{n_ok} liste(s) mise(s) à jour, #{n_err} erreur(s).\n"
elseif next(sources) == nil
  io.stderr\write "Aucune source définie dans cfg.sources — rien à faire.\n"
  os.exit 0

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
