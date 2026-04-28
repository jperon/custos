-- src/auth/sessions.moon
-- Table de sessions en mémoire : MAC → { user, expires (epoch), ips: { ipv4, ipv6 } }
--
-- Persistance via un fichier Lua évaluable (return { ... }) écrit de
-- manière atomique (écriture dans .sessions.lua.new, puis rename).
-- Les workers Q0/Q1 chargent ce fichier via loadfile() avec un cache TTL.

os_time   = os.time
os_rename = os.rename

-- neigh = require "neigh" (chargé dynamiquement dans session_for_mac pour les tests)
{ :log_info } = require "log"

-- ── Sérialisation ────────────────────────────────────────────────

--- Sérialise une table de sessions en code Lua évaluable.
-- @tparam table sessions Table {mac → {user, expires, heartbeat?, ips: {ipv4?, ipv6?}}}
-- @treturn string Code Lua (return { ... })
serialize = (sessions) ->
  parts = { "return {\n" }
  for mac, s in pairs sessions
    safe_mac  = mac\gsub('"', '\\"')
    safe_user = s.user\gsub('"', '\\"')
    hb  = s.heartbeat and (", heartbeat = " .. tostring(s.heartbeat)) or ""

    ips_parts = {}
    if s.ips
      for family, ip in pairs s.ips
        ips_parts[#ips_parts + 1] = string.format('%s = "%s"', family, ip\gsub('"', '\\"'))
    ips_str = #ips_parts > 0 and (", ips = { " .. table.concat(ips_parts, ", ") .. " }") or ""

    parts[#parts + 1] = string.format(
      '  ["%s"] = { user = "%s", expires = %d%s%s },\n',
      safe_mac, safe_user, s.expires, hb, ips_str
    )
  parts[#parts + 1] = "}\n"
  table.concat parts

-- ── Persistance ──────────────────────────────────────────────────

--- Écrit les sessions dans un fichier de manière atomique.
-- @tparam table  sessions Table de sessions
-- @tparam string path     Chemin du fichier de sessions cible
-- @treturn boolean true si l'écriture a réussi
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
load_sessions = (path) ->
  return {} unless path
  fn, _err = loadfile path
  return {} unless fn
  ok, result = pcall fn
  return {} unless ok and type(result) == "table"
  result

-- ── Gestion en mémoire ───────────────────────────────────────────

--- Ajoute ou rafraîchit une session pour une MAC.
-- @tparam table  sessions     Table de sessions (modifiée en place)
-- @tparam string mac          Adresse MAC du client
-- @tparam string ip           Adresse IP courante du client (pour mise à jour ips)
-- @tparam string user         Nom d'utilisateur authentifié
-- @tparam number session_ttl  Durée de vie maximale en secondes
-- @tparam number idle_timeout Délai d'inactivité (heartbeat) en secondes, 0 = désactivé
add_session = (sessions, mac, ip, user, session_ttl, idle_timeout) ->
  return unless mac and mac != "unknown"
  mac = mac\lower!
  now = os_time!
  hb  = (idle_timeout and idle_timeout > 0) and (now + idle_timeout) or nil

  s = sessions[mac] or { ips: {} }
  s.mac = mac
  s.user = user
  s.expires = now + session_ttl
  s.heartbeat = hb

  if ip
    family = if ip\find ":", 1, true then "ipv6" else "ipv4"
    s.ips[family] = ip

  sessions[mac] = s

--- Supprime les sessions expirées.
purge_expired = (sessions) ->
  now = os_time!
  for mac, s in pairs sessions
    if now > s.expires or (s.heartbeat and now > s.heartbeat)
      sessions[mac] = nil

-- ── Cache de lecture (côté workers Q0/Q1) ────────────────────────

_cache      = nil
_cache_time = 0
CACHE_TTL   = 5

read_cached = (path) ->
  now = os_time!
  if not _cache or (now - _cache_time) >= CACHE_TTL
    _cache      = load_sessions path
    _cache_time = now
  _cache

reset_cache = ->
  _cache      = nil
  _cache_time = 0

-- ── Recherche de session ─────────────────────────────────────────

--- Retourne la session valide pour une MAC (ou IP), ou nil.
-- @tparam string|nil mac  Adresse MAC du client (privilégié)
-- @tparam string|nil ip   Adresse IP du client (fallback si MAC absente)
-- @tparam string     path Chemin du fichier de sessions
-- @treturn table|nil Session ou nil
session_for_mac = (mac, ip, path, sessions_arg) ->
  sessions_table = sessions_arg or read_cached path
  return nil unless sessions_table

  lookup_mac = mac

  lookup_mac = (lookup_mac and lookup_mac != "unknown") and lookup_mac\lower! or "unknown"

  s = sessions_table[lookup_mac]

  -- Fallback : si la MAC est inconnue mais qu'une IP est fournie, on cherche
  -- dans toutes les sessions si une d'entre elles possède cette IP.
  if not s and ip
    for m, sess in pairs sessions_table
      if sess.ips
        if sess.ips.ipv4 == ip or sess.ips.ipv6 == ip
          s = sess
          break

  return nil unless s

  -- Si on a l'IP actuelle, on peut mettre à jour le cache ips (en mémoire seulement ici)
  if ip
    family = if ip\find ":", 1, true then "ipv6" else "ipv4"
    s.ips or= {}
    s.ips[family] = ip

  now = os_time!
  return nil if now > s.expires
  return nil if s.heartbeat and now > s.heartbeat
  s

--- Retourne l'utilisateur authentifié pour une MAC/IP, ou nil.
user_for_mac = (mac, ip, path) ->
  s = session_for_mac mac, ip, path
  s and s.user

{
  :serialize, :write_sessions, :load_sessions, :add_session
  :purge_expired, :read_cached, :reset_cache
  :session_for_mac, :user_for_mac
  -- Compatibilité (alias avec réordonnancement des arguments)
  session_for_ip: (ip, path, mac) -> session_for_mac mac, ip, path
  user_for_ip: (ip, path, mac) -> user_for_mac mac, ip, path
}
