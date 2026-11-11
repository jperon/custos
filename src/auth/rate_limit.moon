-- src/auth/rate_limit.moon
-- Limiteur de débit partagé entre les enfants AUTH forké.
--
-- Le worker AUTH traite chaque connexion dans un enfant (fork) : un compteur
-- en mémoire serait donc propre à chaque enfant et ne limiterait rien. L'état
-- est persisté dans un fichier texte simple, lu et réécrit **sous verrou**
-- (lib.filelock.with_lock, le même que le fichier de sessions). Le format
-- (une ligne `clé<TAB>compteur<TAB>reset_at` par entrée) est volontairement
-- non exécutable : un fichier absent, tronqué ou corrompu repart de vide.
--
-- Fenêtre **fixe** par clé : les `limit` premières tentatives d'une fenêtre de
-- `window` secondes sont acceptées, la suivante est refusée avec le nombre de
-- secondes restantes (Retry-After). `limit <= 0` désactive la limitation.
--
-- Entrées bornées : purge de toutes les entrées expirées à chaque écriture,
-- puis plafond MAX_ENTRIES (les entrées dont la fenêtre se termine le plus tôt
-- sont évincées). Le limiteur échoue toujours **ouvert** (état illisible ou
-- verrou indisponible → tentative acceptée) : il ne doit jamais empêcher le
-- portail de répondre.

{ :with_lock } = require "lib.filelock"
{ :ffi } = require "ffi_defs"

DEFAULT_LIMIT  = 3
DEFAULT_WINDOW = 300
MAX_ENTRIES    = 4096

os_time   = os.time
os_rename = os.rename

--- Construit la clé de limitation d'un client.
-- MAC si connue (normalisée en minuscules), sinon IP. Les préfixes évitent
-- qu'une MAC et une IP de même texte se confondent.
-- @tparam string|nil peer_mac Adresse MAC observée sur le paquet
-- @tparam string|nil peer_ip  Adresse IP du client (repli)
-- @treturn string Clé stable (« mac:… », « ip:… » ou « unknown »)
key_for = (peer_mac, peer_ip) ->
  mac = peer_mac and tostring peer_mac
  if mac and mac != "" and mac != "unknown"
    "mac:" .. mac\lower!
  else
    ip = peer_ip and tostring peer_ip
    if ip and ip != ""
      "ip:" .. ip\lower!
    else
      "unknown"

--- Analyse le contenu du fichier d'état ; les lignes invalides sont ignorées.
-- @tparam string content Contenu brut
-- @treturn table Table { clé → { count, reset_at } }
parse_state = (content) ->
  entries = {}
  for line in tostring(content)\gmatch "[^\n]+"
    key, count, reset_at = line\match "^([^\t]+)\t(%d+)\t(%d+)$"
    if key
      entries[key] = { count: tonumber(count), reset_at: tonumber(reset_at) }
  entries

--- Charge l'état ; fichier absent/illisible/corrompu → table vide.
-- @tparam string|nil path Chemin du fichier d'état
-- @treturn table Table { clé → { count, reset_at } }
load_state = (path) ->
  return {} unless path
  fh = io.open path, "r"
  return {} unless fh
  content = fh\read "*a"
  fh\close!
  return {} unless content
  ok, entries = pcall parse_state, content
  return {} unless ok and type(entries) == "table"
  entries

--- Sérialise l'état trié par clé (sortie stable pour les tests et le diff).
-- @tparam table entries Table { clé → { count, reset_at } }
-- @treturn string Contenu du fichier
serialize_state = (entries) ->
  keys = [k for k in pairs entries]
  table.sort keys
  parts = {}
  for key in *keys
    entry = entries[key]
    parts[#parts + 1] = string.format "%s\t%d\t%d\n", key, entry.count, entry.reset_at
  table.concat parts

--- Écrit l'état de façon atomique (temporaire propre au PID puis rename).
-- @tparam table  entries Table { clé → { count, reset_at } }
-- @tparam string path    Chemin cible
-- @treturn boolean true si l'écriture a réussi
write_state = (entries, path) ->
  tmp_path = path .. ".new." .. tostring ffi.C.getpid!
  fh, err = io.open tmp_path, "w"
  unless fh
    os.remove tmp_path
    return false, err
  fh\write serialize_state entries
  fh\close!
  ok, err2 = os_rename tmp_path, path
  unless ok
    os.remove tmp_path
    return false, err2
  true

--- Évince les entrées les plus proches de leur expiration au-delà du plafond.
-- @tparam table  entries Table { clé → { count, reset_at } } (modifiée en place)
-- @tparam number max_entries Plafond d'entrées
trim = (entries, max_entries) ->
  keys = [k for k in pairs entries]
  excess = #keys - max_entries
  return if excess <= 0
  table.sort keys, (a, b) -> entries[a].reset_at < entries[b].reset_at
  for i = 1, excess
    entries[keys[i]] = nil

--- Vérifie et consomme une tentative pour une clé.
-- Toute erreur interne (verrou, I/O) est absorbée et la tentative est acceptée
-- (fail-open) : le limiteur ne doit jamais faire échouer une inscription.
-- @tparam string     path   Chemin du fichier d'état partagé
-- @tparam string     key    Clé du client (cf. key_for)
-- @tparam number|nil limit  Tentatives max par fenêtre (0/nil → défaut/0 = off)
-- @tparam number|nil window Durée de la fenêtre en secondes
-- @tparam number|nil now    Horloge injectable (défaut os.time())
-- @treturn boolean true si la tentative est autorisée
-- @treturn number secondes avant nouvelle tentative (0 si autorisée)
-- @treturn number tentatives restantes dans la fenêtre
check = (path, key, limit, window, now) ->
  limit = tonumber(limit) or DEFAULT_LIMIT
  window = tonumber(window) or DEFAULT_WINDOW
  window = DEFAULT_WINDOW if window <= 0
  return true, 0, math.max 0, limit unless limit > 0 and path

  key = key or "unknown"
  now = tonumber(now) or os_time!

  -- Pré-déclarés : les affectations dans les closures pcall/with_lock ne
  -- créeraient sinon que des locales internes (piège de portée MoonScript).
  allowed, retry_after, remaining = true, 0, math.max 0, limit
  ok = pcall ->
    with_lock path .. ".lock", ->
      entries = load_state path
      for k, entry in pairs entries
        entries[k] = nil if not entry.reset_at or entry.reset_at <= now

      current = entries[key]
      if current and current.count >= limit
        allowed = false
        retry_after = math.max 1, math.ceil(current.reset_at - now)
        write_state entries, path
        return

      unless current
        current = { count: 0, reset_at: now + window }
        entries[key] = current
      current.count += 1
      remaining = math.max 0, limit - current.count
      trim entries, MAX_ENTRIES
      write_state entries, path

  return true, 0, math.max 0, limit unless ok
  allowed, retry_after, remaining

{
  :check, :key_for, :parse_state, :serialize_state
  :DEFAULT_LIMIT, :DEFAULT_WINDOW, :MAX_ENTRIES
}
