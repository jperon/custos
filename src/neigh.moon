-- src/neigh.moon
-- Lecture de la table voisine (ARP/NDP) via `ip neigh show`.
-- Fournit load() pour le pré-remplissage au démarrage et refresh()
-- pour la mise à jour paresseuse (lazy-refresh) lors d'un miss.
--
-- `ip neigh show` fusionne ARP (IPv4) et NDP (IPv6) en une seule commande,
-- ce qui évite d'avoir à lire /proc/net/arp + Netlink séparément.
--
-- Format de sortie (exemple) :
--   192.168.1.5  dev br-lan lladdr aa:bb:cc:dd:ee:ff REACHABLE
--   fd00:28::5   dev br-lan lladdr aa:bb:cc:dd:ee:ff STALE
--   10.0.0.1     dev eth0   lladdr 00:11:22:33:44:55 PERMANENT
--
-- Seuls les états opérationnels sont conservés (les entrées FAILED ou
-- INCOMPLETE n'ont pas encore de MAC résolu).

{ :log_info, :log_warn } = require "log"

-- ── États voisins acceptés ───────────────────────────────────────
-- INCOMPLETE / FAILED : MAC non encore résolu → on ignore
VALID_STATES = {
  REACHABLE: true
  STALE:     true
  DELAY:     true
  PROBE:     true
  PERMANENT: true
  NOARP:     true
}

-- ── Parsing d'une ligne ──────────────────────────────────────────
--- Parse une ligne de `ip neigh show` et retourne {ip, mac} ou nil.
-- Les lignes sans lladdr (INCOMPLETE/FAILED) retournent nil.
-- @tparam string line Ligne brute de `ip neigh show`
-- @treturn table|nil {ip: string, mac: string} ou nil
parse_neigh_line = (line) ->
  -- Format : "<IP> dev <IFACE> lladdr <MAC> [router|proxy|extern_learn ...] <STATE>"
  -- La partie "lladdr <MAC>" est absente pour INCOMPLETE/FAILED.
  -- Le NUD state est toujours le DERNIER mot de la ligne ; des drapeaux
  -- optionnels (`router`, `proxy`, ...) peuvent le précéder.
  ip, mac, tail = line\match "^(%S+)%s+dev%s+%S+%s+lladdr%s+(%S+)%s+(.+)$"
  return nil unless ip and mac and tail
  state = tail\match "(%S+)%s*$"
  return nil unless state and VALID_STATES[state]
  { :ip, :mac }

-- ── Remplissage en place ─────────────────────────────────────────
--- Remplit mac_clients et ip_to_mac depuis la sortie de `ip neigh show`.
-- Les deux tables sont modifiées en place (pas de reset : merge additif).
-- @tparam table  mac_clients  {mac → {ipv4, ipv6, last_seen}}
-- @tparam table  ip_to_mac    {ip_str → mac}
-- @tparam number ts           Timestamp courant (secondes, ex: os.time())
-- @treturn number Nombre d'entrées traitées
fill_from_neigh = (mac_clients, ip_to_mac, ts) ->
  fh = io.popen "ip neigh show 2>/dev/null"
  return 0 unless fh

  count = 0
  for line in fh\lines!
    entry = parse_neigh_line line
    if entry
      mac = entry.mac\lower!
      ip  = entry.ip

      e           = mac_clients[mac] or { ips: {} }
      e.last_seen = ts
      e.ips[ip]   = true

      -- On garde une référence à la dernière IP vue par famille pour la structure e
      family = if ip\find ":", 1, true then "ipv6" else "ipv4"
      e[family] = ip

      mac_clients[mac] = e
      ip_to_mac[ip]    = mac
      count += 1

  fh\close!
  count

-- ── API publique ─────────────────────────────────────────────────

--- Charge la table voisine complète au démarrage.
-- Crée et retourne de nouvelles tables mac_clients et ip_to_mac.
-- @treturn table {mac_clients: table, ip_to_mac: table}
load = ->
  mac_clients = {}
  ip_to_mac   = {}
  ts    = os.time!
  n     = fill_from_neigh mac_clients, ip_to_mac, ts
  log_info { action: "neigh_loaded", entries: n }
  { :mac_clients, :ip_to_mac }

--- Met à jour mac_clients/ip_to_mac en place (lazy-refresh sur miss).
-- Appelé lorsque resolve_client_family() retourne nil et que le
-- cooldown est écoulé.
-- @tparam table mac_clients Table existante à mettre à jour
-- @tparam table ip_to_mac   Table inverse existante à mettre à jour
-- @treturn number Nombre d'entrées traitées
refresh = (mac_clients, ip_to_mac) ->
  ts = os.time!
  n  = fill_from_neigh mac_clients, ip_to_mac, ts
  log_info { action: "neigh_refreshed", entries: n }
  n

_mac_clients = nil
_ip_to_mac = nil
_last_refresh = 0

--- Résout l'adresse MAC d'une IP (standalone, cache interne).
-- Effectue un refresh paresseux (cooldown 5s) si l'IP n'est pas dans le cache.
-- @tparam string ip L'adresse IP à résoudre
-- @treturn string L'adresse MAC, ou "unknown" si introuvable
get_mac = (ip) ->
  unless _mac_clients
    res = load!
    _mac_clients = res.mac_clients
    _ip_to_mac   = res.ip_to_mac
    _last_refresh = os.time!

  return _ip_to_mac[ip] if _ip_to_mac[ip]

  ts = os.time!
  if ts - _last_refresh > 5
    _last_refresh = ts
    refresh _mac_clients, _ip_to_mac
    return _ip_to_mac[ip] or "unknown"

  "unknown"

{ :load, :refresh, :get_mac, :parse_neigh_line, :fill_from_neigh }
