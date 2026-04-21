-- src/auth/sessions.moon
-- Table de sessions en mémoire : IP → { user, expires (epoch) }
--
-- Persistance via un fichier Lua évaluable (return { ... }) écrit de
-- manière atomique (écriture dans .sessions.lua.new, puis rename).
-- Les workers Q0/Q1 chargent ce fichier via loadfile() avec un cache TTL.

os_time   = os.time
os_rename = os.rename

neigh = require "neigh"
{ :log_info } = require "log"

-- ── Sérialisation ────────────────────────────────────────────────

--- Sérialise une table de sessions en code Lua évaluable.
-- @tparam table sessions Table {ip → {user, expires, heartbeat?, mac?}}
-- @treturn string Code Lua (return { ... })
serialize = (sessions) ->
  parts = { "return {\n" }
  for ip, s in pairs sessions
    safe_ip   = ip\gsub('"', '\\"')
    safe_user = s.user\gsub('"', '\\"')
    hb  = s.heartbeat and (", heartbeat = " .. tostring(s.heartbeat)) or ""
    mac = s.mac and (', mac = "' .. s.mac\gsub('"', '\\"') .. '"') or ""
    parts[#parts + 1] = string.format(
      '  ["%s"] = { user = "%s", expires = %d%s%s },\n',
      safe_ip, safe_user, s.expires, hb, mac
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
  return {} unless path  -- garde contre loadfile(nil) qui lit stdin en LuaJIT
  fn, _err = loadfile path
  return {} unless fn
  ok, result = pcall fn
  return {} unless ok and type(result) == "table"
  result

-- ── Gestion en mémoire ───────────────────────────────────────────

--- Ajoute ou rafraîchit une session pour une IP.
-- @tparam table  sessions     Table de sessions (modifiée en place)
-- @tparam string ip           Adresse IP du client
-- @tparam string user         Nom d'utilisateur authentifié
-- @tparam number session_ttl  Durée de vie maximale en secondes
-- @tparam number idle_timeout Délai d'inactivité (heartbeat) en secondes, 0 = désactivé
-- @tparam string|nil mac      Adresse MAC du client (nil si inconnue)
add_session = (sessions, ip, user, session_ttl, idle_timeout, mac) ->
  now = os_time!
  hb  = (idle_timeout and idle_timeout > 0) and (now + idle_timeout) or nil
  sessions[ip] = { :user, expires: now + session_ttl, heartbeat: hb, :mac }

--- Supprime les sessions expirées (purge paresseuse).
-- Tient compte du heartbeat si présent.
-- @tparam table sessions Table de sessions (modifiée en place)
purge_expired = (sessions) ->
  now = os_time!
  for ip, s in pairs sessions
    if now > s.expires or (s.heartbeat and now > s.heartbeat)
      sessions[ip] = nil

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

--- Réinitialise le cache de lecture (pour les tests unitaires).
-- @treturn nil
reset_cache = ->
  _cache      = nil
  _cache_time = 0

--- Retourne la session valide pour une IP, ou nil.
-- Consulte d'abord `sessions[ip]`. Si absent, tente un fallback par MAC
-- (cross-family) : permet qu'un client authentifié en IPv6 soit reconnu
-- quand ses paquets IPv4 arrivent (et réciproquement).
--
-- Le paramètre optionnel `mac` (extraite du paquet par le worker appelant)
-- est privilégié. À défaut, on interroge la table voisine locale via
-- `neigh.get_mac` — utile hors mode bridge, mais inefficace dans le cas
-- où le filtre ne tient pas la table ARP/NDP du LAN.
--
-- Vérifie expiration et heartbeat.
-- @tparam string|nil ip   Adresse IP du client
-- @tparam string     path Chemin du fichier de sessions
-- @tparam string|nil mac  MAC déjà connue du paquet (optionnel)
-- @treturn table|nil Session { user, expires, heartbeat?, mac? } ou nil
session_for_ip = (ip, path, mac) ->
  return nil unless ip
  sessions = read_cached path
  s = sessions[ip]
  unless s
    -- Fallback cross-family par MAC : pref. MAC du paquet, sinon `ip neigh`
    lookup_mac = mac
    unless lookup_mac and lookup_mac != "unknown"
      lookup_mac = neigh.get_mac ip
    if lookup_mac and lookup_mac != "unknown"
      lookup_mac = lookup_mac\lower!
      for sess_ip, s2 in pairs sessions
        -- Cas 1 : la session a une MAC stockée → comparaison directe
        if s2.mac and s2.mac != "unknown"
          if s2.mac\lower! == lookup_mac
            s = s2
            break
        -- Cas 2 : la session n'a pas de MAC (NDP non résolu au login) →
        -- résoudre l'IP de la session via NDP et comparer avec le MAC du paquet.
        elseif not s2.mac or s2.mac == "unknown"
          sess_mac = neigh.get_mac sess_ip
          if sess_mac and sess_mac != "unknown"
            if sess_mac\lower! == lookup_mac
              s = s2
              break
  return nil unless s
  now = os_time!
  return nil if now > s.expires
  return nil if s.heartbeat and now > s.heartbeat
  s

--- Retourne l'utilisateur authentifié pour une IP, ou nil.
-- Destiné aux workers (Q0/Q1/Q2) pour enrichir leurs logs.
-- @tparam string|nil ip   Adresse IP du client
-- @tparam string     path Chemin du fichier de sessions
-- @tparam string|nil mac  MAC déjà connue du paquet (optionnel)
-- @treturn string|nil Nom d'utilisateur authentifié, ou nil
user_for_ip = (ip, path, mac) ->
  s = session_for_ip ip, path, mac
  s and s.user

{ :serialize, :write_sessions, :load_sessions, :add_session, :purge_expired, :read_cached, :reset_cache, :session_for_ip, :user_for_ip }
