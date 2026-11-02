-- src/filter/updater_io.moon
-- Helpers d'I/O shell de l'updater (téléchargement, création de répertoires).
--
-- Isolés du script `filter/updater.moon` (qui s'exécute au chargement) pour
-- être testables unitairement. En particulier `download_file` doit gérer les
-- deux sémantiques de `os.execute` (Lua 5.1 : code numérique ; Lua 5.2+ /
-- LUA52COMPAT : true/nil), via `lib.os_exec.exec_ok`.

exec_ok = require("lib.os_exec").exec_ok

--- Quote une valeur pour un usage sûr dans une commande shell POSIX.
-- @tparam string s Valeur à échapper
-- @treturn string Valeur entourée de quotes simples avec échappement interne
sh_quote = (s) ->
  "'" .. tostring(s)\gsub("'", "'\"'\"'") .. "'"

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

{ :sh_quote, :ensure_dir, :ensure_parent_dir, :download, :download_file }
