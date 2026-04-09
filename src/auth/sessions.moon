-- src/auth/sessions.moon
-- Table de sessions en mémoire : IP → { user, expires (epoch) }
--
-- Persistance via un fichier Lua évaluable (return { ... }) écrit de
-- manière atomique (écriture dans .sessions.lua.new, puis rename).
-- Les workers Q0/Q1 chargent ce fichier via loadfile() avec un cache TTL.

os_time   = os.time
os_rename = os.rename

-- ── Sérialisation ────────────────────────────────────────────────

--- Sérialise une table de sessions en code Lua évaluable.
-- @tparam table sessions Table {ip → {user, expires}}
-- @treturn string Code Lua (return { ... })
serialize = (sessions) ->
  parts = { "return {\n" }
  for ip, s in pairs sessions
    safe_ip   = ip\gsub('"', '\\"')
    safe_user = s.user\gsub('"', '\\"')
    parts[#parts + 1] = string.format(
      '  ["%s"] = { user = "%s", expires = %d },\n',
      safe_ip, safe_user, s.expires
    )
  parts[#parts + 1] = "}\n"
  table.concat parts

-- ── Persistance ──────────────────────────────────────────────────

--- Écrit les sessions dans un fichier de manière atomique.
-- Utilise un fichier temporaire + rename pour éviter les lectures partielles.
-- @tparam table  sessions Table de sessions
-- @tparam string path     Chemin du fichier de sessions cible
-- @treturn boolean true si l'écriture a réussi
-- @treturn nil|string Message d'erreur
write_sessions = (sessions, path) ->
  tmp_path = path .. ".new"
  fh, err = io.open tmp_path, "w"
  return false, "impossible d'écrire #{tmp_path} : #{err}" unless fh
  fh\write serialize sessions
  fh\close!
  ok, err2 = os_rename tmp_path, path
  return false, "rename() échoué : #{tostring err2}" unless ok
  true

--- Charge les sessions depuis un fichier Lua.
-- Retourne une table vide si le fichier est absent ou invalide.
-- @tparam string path Chemin du fichier de sessions
-- @treturn table Table {ip → {user, expires}}
load_sessions = (path) ->
  fn, _err = loadfile path
  return {} unless fn
  ok, result = pcall fn
  return {} unless ok and type(result) == "table"
  result

-- ── Gestion en mémoire ───────────────────────────────────────────

--- Ajoute ou rafraîchit une session pour une IP.
-- @tparam table  sessions    Table de sessions (modifiée en place)
-- @tparam string ip          Adresse IP du client
-- @tparam string user        Nom d'utilisateur authentifié
-- @tparam number session_ttl Durée de vie en secondes
add_session = (sessions, ip, user, session_ttl) ->
  sessions[ip] = { :user, expires: os_time! + session_ttl }

--- Supprime les sessions expirées (purge paresseuse).
-- @tparam table sessions Table de sessions (modifiée en place)
purge_expired = (sessions) ->
  now = os_time!
  for ip, s in pairs sessions
    sessions[ip] = nil if now > s.expires

-- ── Cache de lecture (côté workers Q0/Q1) ────────────────────────
-- Chaque worker maintient son propre cache local (processus séparés).

_cache      = nil
_cache_time = 0
CACHE_TTL   = 5   -- secondes entre deux lectures du fichier

--- Lit les sessions avec cache TTL, pour les workers Q0/Q1.
-- Recharge le fichier au plus toutes les CACHE_TTL secondes.
-- @tparam string path Chemin du fichier de sessions
-- @treturn table Table de sessions (peut être vide)
read_cached = (path) ->
  now = os_time!
  if not _cache or (now - _cache_time) >= CACHE_TTL
    _cache      = load_sessions path
    _cache_time = now
  _cache

{ :serialize, :write_sessions, :load_sessions, :add_session
  :purge_expired, :read_cached }
