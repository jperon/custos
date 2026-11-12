-- src/filter/updater_io.moon
-- Helpers d'I/O shell de l'updater (téléchargement, création de répertoires).
--
-- Isolés du script `filter/updater.moon` (qui s'exécute au chargement) pour
-- être testables unitairement. En particulier `download_file` doit gérer les
-- deux sémantiques de `os.execute` (Lua 5.1 : code numérique ; Lua 5.2+ /
-- LUA52COMPAT : true/nil), via `lib.os_exec.exec_ok`.

ffi = require "ffi"
bin48 = require "filter.lib.bin48"
parse_domains = require "filter.lib.parse_domains"
exec_ok = require("lib.os_exec").exec_ok

ffi.cdef [[
  int rename(const char *oldpath, const char *newpath);
]]

--- Quote une valeur pour un usage sûr dans une commande shell POSIX.
-- @tparam string s Valeur à échapper
-- @treturn string Valeur entourée de quotes simples avec échappement interne
sh_quote = (s) ->
  "'" .. tostring(s)\gsub("'", "'\"'\"'") .. "'"

--- Nom de base d'une liste compilée, à partir de son fichier source `.txt`.
-- Retire le répertoire et le suffixe `.txt` ; sans suffixe, garde le nom tel quel.
-- @tparam string txt_name Nom de fichier source (ex. "groupe/ads.txt")
-- @treturn string Nom de base du `.bin` (ex. "ads")
bin_name_for = (txt_name) ->
  (txt_name\match "([^/]+)%.txt$") or txt_name

--- Classe le résultat d'une écriture de liste (.bin).
-- @tparam boolean ok      Succès de l'écriture
-- @tparam string  _msg    Message (non utilisé)
-- @tparam boolean skipped Vrai si liste vide (non-erreur)
-- @treturn string "ok" | "skipped" | "error"
write_result_kind = (ok, _msg, skipped) ->
  return "ok" if ok
  return "skipped" if skipped
  "error"

--- Crée un répertoire (et ses parents) si nécessaire.
-- @tparam string dir Chemin du répertoire
-- @treturn boolean true si OK
ensure_dir = (dir) ->
  return true unless dir and dir != ""
  ret = os.execute "mkdir -p #{sh_quote(dir)}"
  exec_ok ret

--- Crée le répertoire parent d'un chemin fichier, si nécessaire.
-- @tparam string path Chemin de fichier
-- @treturn boolean true si OK (ou non nécessaire), false sinon
ensure_parent_dir = (path) ->
  parent = tostring(path)\match "^(.*)/[^/]+$"
  return true unless parent and parent != ""
  ret = os.execute "mkdir -p #{sh_quote(parent)}"
  exec_ok ret

--- Télécharge une URL via curl et retourne le contenu.
-- Utilise curl avec un timeout de 30 s et --fail pour détecter les erreurs HTTP.
-- @tparam  string      url URL à télécharger
-- @treturn string|nil  Contenu, ou nil en cas d'erreur
-- @treturn nil|string  Message d'erreur
download = (url) ->
  cmd = "curl --silent --location --max-time 30 --fail " .. sh_quote(url)
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
  cmd = "curl --silent --location --max-time #{timeout} --fail -o #{sh_quote(dest)} #{sh_quote(url)}"
  ret = os.execute cmd
  exec_ok ret

--- Hash, trie et écrit un ensemble de domaines dans un fichier .bin.
-- Le fichier est écrit de façon atomique via un fichier temporaire.
-- Une liste vide est écrite comme un .bin de 0 octet : c'est une liste vide
-- VALIDE (le filtre la charge et ne logue pas `filter_list_missing`), et non
-- une raison de ne rien produire.
-- @tparam  table   domains     Tableau de chaînes de domaines
-- @tparam  string  output_path Chemin du fichier .bin de destination
-- @tparam  boolean dry_run     Si vrai, n'écrit pas
-- @treturn boolean             Succès
-- @treturn string              Message (nb domaines ou erreur)
-- @treturn boolean             Vrai si la liste est vide (non-erreur)
write_bin = (domains, output_path, dry_run) ->
  payload, n = bin48.pack_domains domains

  if dry_run
    return true, "dry-run : #{n} domaines → #{output_path}"

  tmp = output_path .. ".tmp"
  unless ensure_parent_dir tmp
    return false, "impossible de créer le répertoire parent de #{tmp}"
  fh = io.open tmp, "wb"
  return false, "impossible d'écrire #{tmp}" unless fh
  fh\write payload
  fh\close!

  ret = ffi.C.rename tmp, output_path
  if ret ~= 0
    os.remove tmp
    return false, "rename échoué : #{tmp} → #{output_path}"

  if n == 0
    return true, "liste vide (0 domaine) → #{output_path}", false
  true, "#{n} domaines → #{output_path} (#{#payload} octets)"

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

--- Parcourt un répertoire source et compile tous les fichiers .txt en .bin.
-- Les fichiers .txt originaux sont conservés dans src_dir.
-- Les .bin sont écrits dans output_dir (défaut : src_dir).
-- Cela permet de séparer les sources (ex. /etc/custos/lists/custom/) de
-- la sortie compilée lue par le filtre (ex. domainlists_dir/custom/).
-- @tparam  string   src_dir    Répertoire contenant les .txt à compiler
-- @tparam  string   output_dir Répertoire de destination des .bin (défaut : src_dir)
-- @tparam  boolean  dry_run
-- @treturn number              Nombre de listes mises à jour
-- @treturn number              Nombre d'erreurs
process_custom_dir = (src_dir, output_dir, dry_run) ->
  output_dir = output_dir or src_dir
  local_updated, local_errors = 0, 0
  ensure_dir src_dir
  ensure_dir output_dir
  quoted_dir = sh_quote src_dir
  fh = io.popen "cd #{quoted_dir} 2>/dev/null && ls -1 *.txt 2>/dev/null"
  unless fh
    return 0, 0
  src_base = src_dir\gsub "/+$", ""
  out_base = output_dir\gsub "/+$", ""
  for txt_name in fh\lines!
    txt_name = txt_name\gsub "%s+$", ""
    continue if txt_name == ""
    txt_path = src_base .. "/" .. txt_name
    name = bin_name_for txt_name
    bin_path = out_base .. "/" .. name .. ".bin"
    ok_l, msg, skipped = fetch_local name, { file: txt_path, format: "simple", output: bin_path }, dry_run
    kind = write_result_kind ok_l, msg, skipped
    if kind == "ok"
      io.stderr\write "[custom/#{name}] ✓ #{msg}\n"
      local_updated += 1
    elseif kind == "skipped"
      io.stderr\write "[custom/#{name}] ⏭ ignorée (#{msg})\n"
    else
      io.stderr\write "[custom/#{name}] ✗ #{msg}\n"
      local_errors += 1
  fh\close!
  local_updated, local_errors

{ :sh_quote, :bin_name_for, :write_result_kind, :ensure_dir, :ensure_parent_dir,
  :download, :download_file, :write_bin, :fetch_local, :process_custom_dir }
