-- src/auth/captive.moon
-- Serveur HTTP plain du portail captif.
--
-- Écoute sur le port 33080. Reçoit les connexions HTTP redirigées par nft DNAT
-- (tcp dport 80 → redirect to :33080). Répond systématiquement avec un 302
-- vers la page de login HTTPS. Gère les sondes OS de détection de portail captif.
--
-- Dépendances : luasocket, log.

socket = require "socket"
neigh  = require "neigh"
{ :log_info } = require "log"

-- Chemins de détection des portails captifs des principaux OS.
-- Tous reçoivent un 302 (non-204 pour Android, suivi de 302 pour les autres).
DETECTION_PATHS = {
  "/generate_204"             -- Android / Chrome OS
  "/hotspot-detect.html"      -- macOS / iOS
  "/library/test/success.html" -- macOS (ancien)
  "/connecttest.txt"          -- Windows 10+
  "/ncsi.txt"                 -- Windows (ancien)
  "/success.txt"              -- Firefox / Ubuntu
  "/canonical.html"           -- Ubuntu
}

--- Vérifie si un chemin est une sonde OS de détection de portail captif.
-- @tparam  string path  Chemin URL (peut contenir query string)
-- @treturn boolean
is_detection_path = (path) ->
  clean = path\match("^([^?#]+)") or path
  for p in *DETECTION_PATHS
    return true if clean == p
  false

--- Détecte l'adresse IP locale de la machine filtre (interface vers le LAN).
-- Utilise un socket UDP connecté sans envoi réel de paquet.
-- @treturn string  IP locale (ex. "10.99.0.254"), ou "127.0.0.1" en cas d'échec
detect_local_ip = ->
  u = socket.udp!
  pcall -> u\connect "8.8.8.8", 80
  ip, _ = u\getsockname!
  u\close!
  (ip and ip != "" and ip != "0.0.0.0") and ip or "127.0.0.1"

--- Gère une connexion HTTP du portail captif et répond avec un 302.
-- L'IP locale est obtenue depuis le socket accepté pour construire l'URL de redirection,
-- ce qui fonctionne correctement sur un routeur multi-interfaces.
-- @tparam table  client     Socket TCP client (plain, sans TLS)
-- @tparam number auth_port  Port HTTPS du serveur d'authentification (ex. 33443)
handle_connection = (client, auth_port) ->
  client\settimeout 5

  -- Lire la ligne de requête
  line, _ = client\receive "*l"
  unless line
    client\close!
    return

  -- Lire et jeter les headers HTTP (évite RST avant que le client lise la réponse)
  while true
    hline, _ = client\receive "*l"
    break if not hline or hline == ""

  path = line\match("^%u+%s+([^%s]+)") or "/"

  -- IP locale = interface LAN du filtre qui a reçu la connexion
  local_ip, _ = client\getsockname!
  local_ip = local_ip or "127.0.0.1"
  -- Entoure les adresses IPv6 de crochets pour former une URL valide
  host_part = local_ip\find(":", 1, true) and "[#{local_ip}]" or local_ip
  redirect_url = "https://#{host_part}:#{auth_port}/"

  resp = "HTTP/1.1 302 Found\r\nLocation: #{redirect_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  client\send resp

  -- IP du client
  peer_ip, _ = client\getpeername!
  peer_ip = tostring peer_ip
  peer_mac = neigh.get_mac peer_ip

  if is_detection_path path
    log_info { action: "captive_probe", path: path, ip: peer_ip, mac: peer_mac }
  else
    log_info { action: "captive_redirect", path: path, ip: peer_ip, mac: peer_mac }

  client\close!

--- Crée un socket serveur TCP IPv4 pour le portail captif.
-- @tparam number port  Port d'écoute (ex. 33080)
-- @treturn table|nil   Socket serveur, ou nil + message d'erreur
make_captive4 = (port) ->
  srv = socket.tcp!
  srv\setoption "reuseaddr", true
  ok, err = srv\bind "0.0.0.0", port
  unless ok
    srv\close!
    return nil, err
  srv\listen 8
  srv\settimeout 1
  srv

--- Crée un socket serveur TCP IPv6 pour le portail captif.
-- @tparam number port  Port d'écoute
-- @treturn table|nil   Socket serveur, ou nil (IPv6 indisponible — non fatal)
make_captive6 = (port) ->
  ok6, srv6 = pcall socket.tcp6
  return nil unless ok6 and srv6
  srv6\setoption "reuseaddr", true
  srv6\setoption "ipv6-v6only", true
  ok62, _ = srv6\bind "::", port
  unless ok62
    srv6\close!
    return nil
  srv6\listen 8
  srv6\settimeout 1
  srv6

{ :handle_connection, :make_captive4, :make_captive6 }
