-- src/lib/pidfile.moon
-- Pidfile du superviseur : source unique du PID qui traite SIGHUP pour le
-- hot-reload de la config (cf. src/main.moon). Écrit par le superviseur au
-- démarrage, lu par la webui (« Recharger maintenant ») et custos-update pour
-- viser le bon processus — et non le worker AUTH, qui ne relit que les secrets.

-- Chemin par défaut, surchargeable via env CUSTOS_PID_FILE ou clé de config
-- runtime.pid_file (résolu par l'appelant).
DEFAULT_PATH = "/var/run/custos.pid"

--- Résout le chemin du pidfile.
-- @tparam ?string cfg_path valeur de config (runtime.pid_file), prioritaire
-- @treturn string chemin effectif
resolve_path = (cfg_path) ->
  cfg_path or os.getenv("CUSTOS_PID_FILE") or DEFAULT_PATH

--- Écrit `pid` dans le pidfile. Best-effort : ne lève jamais.
-- @tparam number pid PID à écrire
-- @tparam ?string path chemin (défaut : résolu)
-- @treturn boolean true si l'écriture a réussi
write = (pid, path) ->
  path or= resolve_path!
  ok = pcall ->
    fh = assert io.open path, "w"
    fh\write tostring pid
    fh\close!
  ok

--- Supprime le pidfile. Best-effort.
-- @tparam ?string path chemin (défaut : résolu)
remove = (path) ->
  path or= resolve_path!
  pcall -> os.remove path
  nil

--- Lit le PID stocké.
-- @tparam ?string path chemin (défaut : résolu)
-- @treturn number|nil PID, ou nil si absent/illisible/invalide
-- @treturn ?string message d'erreur si nil
read = (path) ->
  path or= resolve_path!
  fh = io.open path, "r"
  return nil, "pidfile introuvable : #{path}" unless fh
  content = fh\read "*a"
  fh\close!
  pid = tonumber (content or "")\match "%d+"
  return nil, "pidfile illisible : #{path}" unless pid and pid > 0
  pid

{ :resolve_path, :write, :remove, :read, :DEFAULT_PATH }
