-- src/auth/sessions.moon
-- Table de sessions en mémoire : MAC → { user, expires? (epoch), ips: { ipv4, ipv6 } }
--
-- Persistance via un fichier Lua évaluable (return { ... }) écrit de
-- manière atomique (écriture dans .sessions.lua.new, puis rename).
-- Les workers question/response chargent ce fichier via loadfile() avec un cache TTL.

os_time   = os.time
os_rename = os.rename

-- neigh = require "neigh" (chargé dynamiquement dans session_for_mac pour les tests)
{ :log_info } = require "log"
{ :ffi, :libc } = require "ffi_defs"

-- ── Signature de fichier (statx) ─────────────────────────────────────────────
-- Permet de prouver qu'un fichier de sessions n'a PAS changé depuis le dernier
-- chargement, et donc qu'un reload serait un no-op strict. Utilisé pour éviter
-- les `loadfile` redondants sur le hot-path question/response SANS jamais
-- introduire de faux négatif : on ne saute un reload que si statx réussit ET
-- renvoie une signature identique. Tout échec statx → signature nil → reload.
AT_FDCWD          = -100
AT_STATX_SYNC_AS_STAT = 0x0000   -- comportement stat(2) standard
STATX_BASIC_STATS = 0x000007ff   -- mtime + size + ino inclus
_statx_buf = ffi.new "struct statx[1]"

--- Retourne une signature compacte (mtime_ns + size + ino) du fichier, ou nil.
-- nil signifie « impossible de prouver l'identité » (fichier absent, statx
-- indisponible, erreur) → l'appelant doit recharger par sécurité.
-- @tparam string path Chemin du fichier
-- @treturn string|nil Signature opaque, ou nil
file_sig = (path) ->
  return nil unless path
  ok, rv = pcall libc.statx, AT_FDCWD, path, AT_STATX_SYNC_AS_STAT, STATX_BASIC_STATS, _statx_buf
  return nil unless ok and rv == 0
  s = _statx_buf[0]
  m = s.stx_mtime
  string.format "%d.%09d:%d:%d",
    tonumber(m.tv_sec), tonumber(m.tv_nsec),
    tonumber(s.stx_size), tonumber(s.stx_ino)

-- ── Sérialisation ────────────────────────────────────────────────

--- Sérialise une table de sessions en code Lua évaluable.
-- @tparam table sessions Table {mac → {user, expires, ips: {ipv4?, ipv6?}}}
-- @treturn string Code Lua (return { ... })
serialize = (sessions) ->
  parts = { "return {\n" }
  for mac, s in pairs sessions
    safe_mac  = mac\gsub('"', '\\"')
    safe_user = s.user\gsub('"', '\\"')
    expires_str = s.expires and (", expires = " .. tostring(s.expires)) or ""

    ips_parts = {}
    if s.ips
      for family, ip in pairs s.ips
        ips_parts[#ips_parts + 1] = string.format('%s = "%s"', family, ip\gsub('"', '\\"'))
    ips_str = #ips_parts > 0 and (", ips = { " .. table.concat(ips_parts, ", ") .. " }") or ""

    parts[#parts + 1] = string.format(
      '  ["%s"] = { user = "%s"%s%s, mac = "%s" },\n',
      safe_mac, safe_user, expires_str, ips_str, safe_mac
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
-- expires est le timestamp absolu d'expiration (os.time() + ttl).
-- Avec le mécanisme de rolling refresh du token, le caller passe
-- systématiquement now + idle_timeout, rafraîchi à chaque ping.
-- @tparam table  sessions  Table de sessions (modifiée en place)
-- @tparam string mac       Adresse MAC du client
-- @tparam string ip        Adresse IP courante (pour mise à jour ips)
-- @tparam string user      Nom d'utilisateur authentifié
-- @tparam number expires   Timestamp d'expiration (os.time() + ttl)
add_session = (sessions, mac, ip, user, expires) ->
  return unless mac and mac != "unknown"
  mac = mac\lower!

  s = sessions[mac] or { ips: {} }
  s.mac     = mac
  s.user    = user
  s.expires = expires

  if ip
    family = if ip\find ":", 1, true then "ipv6" else "ipv4"
    s.ips[family] = ip

  sessions[mac] = s

--- Supprime les sessions expirées.
purge_expired = (sessions) ->
  now = os_time!
  for mac, s in pairs sessions
    sessions[mac] = nil if s.expires and now > s.expires

-- ── Cache de lecture (côté workers question/response) ────────────────────────

_cache      = nil
_cache_time = 0
_cache_sig  = nil
CACHE_TTL   = 5

read_cached = (path) ->
  now = os_time!
  if not _cache or (now - _cache_time) >= CACHE_TTL
    _cache      = load_sessions path
    _cache_time = now
    _cache_sig  = file_sig path
  _cache

reload_cached = (path) ->
  _cache      = load_sessions path
  _cache_time = os_time!
  _cache_sig  = file_sig path
  _cache

reset_cache = ->
  _cache      = nil
  _cache_time = 0
  _cache_sig  = nil

-- Détermine si un reload-on-miss est nécessaire. On ne l'évite (retourne false)
-- QUE si on peut prouver que le fichier est byte-identique à la version en cache
-- (signature statx présente des deux côtés et égale) : recharger redonnerait
-- alors exactement la même table — no-op strict, donc zéro faux négatif. Tout
-- autre cas (signature absente, différente, statx en échec) → reload.
reload_needed = (path) ->
  cur = file_sig path
  return true unless cur and _cache_sig
  cur != _cache_sig

--- Enrichit une session existante avec une nouvelle IP (sans écraser l'existante).
-- Utile pour enregistrer les deux IPs (IPv4 et IPv6) d'un client authentifié.
-- Relit le fichier, enrichit, et réécrit si changement.
-- @tparam string mac   Adresse MAC du client
-- @tparam string ip    Adresse IP à enregistrer (IPv4 ou IPv6)
-- @tparam string path  Chemin du fichier de sessions
-- @treturn boolean true si enrichissement a eu lieu
valid_mac = (mac) ->
  mac and mac != "unknown" and mac != "\x00\x00\x00\x00\x00\x00"

find_session_by_ip = (sessions, ip) ->
  return nil, nil unless ip
  for m, sess in pairs sessions
    if sess.ips and (sess.ips.ipv4 == ip or sess.ips.ipv6 == ip)
      return m, sess
  nil, nil

enrich_session_ip = (mac, ip, path) ->
  return false unless valid_mac(mac) and ip and path
  mac = mac\lower!

  sessions = load_sessions path
  s = sessions[mac]
  unless s
    _old_mac, found = find_session_by_ip sessions, ip
    s = found
  return false unless s

  family = if ip\find ":", 1, true then "ipv6" else "ipv4"
  s.ips or= {}

  -- Ne pas écraser une IP existante de la même famille
  if s.ips[family] and s.ips[family] != ip
    return false  -- IP différente pour cette famille : pas d'enrichissement

  if s.ips[family] == ip and sessions[mac] == s
    return false  -- Déjà présente sous cette MAC : rien à faire

  -- Nouvelle IP ou session trouvée par IP sous une autre MAC : enregistrer
  -- sous la MAC réellement observée sur le paquet DNS.
  s.ips[family] = ip
  s.mac = mac
  sessions[mac] = s
  write_sessions sessions, path
  reset_cache!  -- Invalider le cache pour que la nouvelle IP soit lue prochainement

  true

bind_session_mac = (session_mac, current_mac, ip, path) ->
  return false unless valid_mac(current_mac) and path
  current_mac = current_mac\lower!
  session_mac = session_mac and session_mac\lower! or nil
  return enrich_session_ip current_mac, ip, path if session_mac == current_mac

  sessions = load_sessions path
  s = (session_mac and sessions[session_mac]) or nil
  unless s
    _old_mac, found = find_session_by_ip sessions, ip
    session_mac = _old_mac
    s = found
  return false unless s

  s.mac = current_mac
  if ip
    family = if ip\find ":", 1, true then "ipv6" else "ipv4"
    s.ips or= {}
    s.ips[family] or= ip

  sessions[current_mac] = s
  sessions[session_mac] = nil if session_mac and session_mac != current_mac
  write_sessions sessions, path
  reset_cache!
  true

-- ── Recherche de session ─────────────────────────────────────────

lookup_session = (sessions_table, lookup_mac, ip) ->
  s = sessions_table[lookup_mac]

  -- Fallback : si la MAC est inconnue mais qu'une IP est fournie, on cherche
  -- dans toutes les sessions si une d'entre elles possède cette IP exacte.
  if not s and ip
    for m, sess in pairs sessions_table
      if sess.ips
        if sess.ips.ipv4 == ip or sess.ips.ipv6 == ip
          s = sess
          s.mac = m
          break

  s

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

  s = lookup_session sessions_table, lookup_mac, ip

  -- Les workers question/response gardent un cache court. Juste après une authentification,
  -- ce cache peut être encore vide ou obsolète : en cas de miss, relire le
  -- fichier immédiatement avant de refuser. Les hits gardent le chemin rapide.
  if not s and not sessions_arg and path and reload_needed path
    sessions_table = reload_cached path
    s = lookup_session sessions_table, lookup_mac, ip if sessions_table

  return nil unless s

  now = os_time!
  if s.expires and now > s.expires
    if not sessions_arg and path and reload_needed path
      sessions_table = reload_cached path
      s = lookup_session sessions_table, lookup_mac, ip if sessions_table
      return nil unless s
      now = os_time!
    return nil if s.expires and now > s.expires

  -- Si on a l'IP actuelle, on peut mettre à jour le cache ips (en mémoire seulement ici)
  if ip
    family = if ip\find ":", 1, true then "ipv6" else "ipv4"
    s.ips or= {}
    s.ips[family] or= ip

  s

--- Retourne l'utilisateur authentifié pour une MAC/IP, ou nil.
user_for_mac = (mac, ip, path) ->
  s = session_for_mac mac, ip, path
  s and s.user

{
  :serialize, :write_sessions, :load_sessions, :add_session
  :purge_expired, :read_cached, :reset_cache
  :session_for_mac, :user_for_mac, :enrich_session_ip, :bind_session_mac
}
