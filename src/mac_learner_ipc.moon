-- src/mac_learner_ipc.moon
-- Client IPC pour le worker MAC Learner (query-only).
--
-- Fourni uniquement la fonction `get_mac(ip_str)` qui interroge le socket
-- Unix du learner et retourne la MAC textuelle ou "unknown".
--
-- Anciennement ce module fournissait aussi `learn()` (question → learner via pipe).
-- Aujourd'hui l'apprentissage se fait via le worker mac_learner (socket Unix).
-- `learn()` n'est plus nécessaire ici.

{ :ffi, :libc } = require "ffi_defs"
config = require "config"
{ :log_warn } = require "log"

learner_cfg = config.mac_learner or {}
QUERY_SOCK = learner_cfg.query_sock or config.MAC_LEARNER_QUERY_SOCK or "/var/run/custos/mac_query.sock"

AF_UNIX     = 1
AF_INET6    = 10
SOCK_STREAM = 1

-- Bornes des send/recv bloquants vers le learner. Doit rester supérieur au
-- PROBE_TIMEOUT_MS (200 ms) du learner, qui peut retenir la réponse le temps
-- d'un sondage ARP/NS ; sans cela un learner figé bloquerait le plan de données
-- (worker_responses/worker_tls/worker_doh).
SOL_SOCKET      = 1
SO_RCVTIMEO     = 20
SO_SNDTIMEO     = 21
QUERY_TIMEOUT_S = 0.5

bit = require "bit"
{ :mac2s } = require "packet_utils"

--- Pose un timeout (secondes, fractions acceptées) sur un fd de socket.
-- Best-effort : un mock de libc en test peut ne pas exposer setsockopt.
-- @tparam number fd      Descripteur de socket
-- @tparam number optname SO_RCVTIMEO ou SO_SNDTIMEO
-- @tparam number secs    Délai maximal
set_socket_timeout = (fd, optname, secs) ->
  pcall ->
    tv = ffi.new "struct timeval"
    tv.tv_sec  = math.floor secs
    tv.tv_usec = math.floor (secs - math.floor(secs)) * 1e6
    libc.setsockopt fd, SOL_SOCKET, optname, tv, ffi.sizeof tv

--- Interroge le learner : connect, send, recv, close.
-- Squelette commun à get_mac/get_vlan/strip_target, borné dans le temps par
-- SO_RCVTIMEO/SO_SNDTIMEO. Un timeout ou une erreur rend nil (traité comme
-- « inconnu » par l'appelant).
-- @tparam string request Ligne de requête terminée par \n
-- @treturn string|nil Réponse brute, ou nil si échec/timeout
query = (request) ->
  sock = libc.socket AF_UNIX, SOCK_STREAM, 0
  unless sock >= 0
    log_warn -> { action: "mac_ipc_socket_failed", errno: tonumber(ffi.C.__errno_location()[0]) }
    return nil

  addr = ffi.new "struct sockaddr_un"
  addr.sun_family = AF_UNIX
  ffi.copy addr.sun_path, QUERY_SOCK
  -- addrlen = offset de sun_path + longueur du chemin + '\0'
  addr_len = ffi.offsetof("struct sockaddr_un", "sun_path") + #QUERY_SOCK + 1

  if libc.connect(sock, ffi.cast("struct sockaddr*", addr), addr_len) ~= 0
    libc.close sock
    return nil

  set_socket_timeout sock, SO_RCVTIMEO, QUERY_TIMEOUT_S
  set_socket_timeout sock, SO_SNDTIMEO, QUERY_TIMEOUT_S

  libc.send sock, request, #request, 0

  buf = ffi.new "char[64]"
  n = libc.recv sock, buf, 63, 0
  libc.close sock

  return nil if n <= 0

  ffi.string buf, n

--- Tente de dériver une adresse MAC depuis l'identifiant EUI-64 d'une adresse IPv6.
-- Un identifiant EUI-64 est reconnaissable aux octets 11 et 12 (0-indexés) de
-- l'adresse IPv6 qui valent 0xff et 0xfe. La reconstruction inverse :
--   MAC = (addr[8] XOR 0x02) : addr[9] : addr[10] : addr[13] : addr[14] : addr[15]
-- Ne fonctionne pas avec les adresses à identifiants opaques (RFC 7217)
-- ni avec les privacy extensions (RFC 4941).
-- @tparam string ip_str Adresse IPv6 textuelle
-- @treturn string|nil MAC "aa:bb:cc:dd:ee:ff", ou nil si non-EUI-64 ou parse échoué
mac_from_eui64 = (ip_str) ->
  -- Rejeter nil et les IPv4 (pas de ':')
  return nil unless ip_str
  return nil unless ip_str\find ":", 1, true

  -- Parser l'adresse IPv6 en binaire
  buf = ffi.new "uint8_t[16]"
  return nil if libc.inet_pton(AF_INET6, ip_str, buf) ~= 1

  -- Détecter l'identifiant EUI-64 : bytes 11-12 (0-indexés) == 0xff 0xfe
  return nil unless buf[11] == 0xff and buf[12] == 0xfe

  -- Reconstruire la MAC : inverser le flip du bit U/L, retirer les octets ff:fe
  b0 = bit.bxor buf[8], 0x02
  mac2s string.char b0, buf[9], buf[10], buf[13], buf[14], buf[15]

--- Retourne la MAC associée à une IP via une requête au MAC learner.
-- Connexion synchrone sur socket Unix SOCK_STREAM : approprié pour AUTH
-- (une requête par connexion entrante) et pour captive (SYNs rate-limités par nft).
-- @tparam string ip_str Adresse IP sous forme de chaîne
-- @treturn string MAC "aa:bb:cc:dd:ee:ff" ou "unknown"
get_mac = (ip_str) ->
  return "unknown" unless ip_str and ip_str ~= "" and ip_str ~= "unknown"

  resp = query ip_str .. "\n"
  if resp
    -- Extrait la MAC (format "xx:xx:xx:xx:xx:xx") ou "unknown"
    mac = resp\match "^([0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f])"
    return mac if mac

  -- Fallback EUI-64 : si le learner ne connaît pas cette adresse IPv6 mais
  -- qu'elle encode une MAC EUI-64, on la dérive directement sans apprentissage.
  mac = mac_from_eui64 ip_str
  return mac if mac

  "unknown"

--- Retourne le VLAN ID associé à une IP via une requête au MAC learner.
-- Interroge le même socket Unix que get_mac avec le préfixe "vlan:".
-- Contrat : retourne un `number` (≥ 0, où `0` = untagged observé) si le learner
-- a vu cette IP, ou `nil` si elle est inconnue (jamais observée par la file DoH).
-- Cette distinction permet l'écrasement anti-stale (cf. plan, § Sécurité).
-- @tparam string ip_str Adresse IP sous forme de chaîne
-- @treturn number|nil VLAN ID observé (0 = untagged), ou nil si inconnu
get_vlan = (ip_str) ->
  return nil unless ip_str and ip_str ~= "" and ip_str ~= "unknown"

  resp = query "vlan:" .. ip_str .. "\n"
  return nil unless resp

  id = resp\match "^(%d+)"
  return tonumber(id) if id

  nil

--- Parse la réponse du learner à une requête strip.
-- @tparam string resp Réponse brute reçue sur le socket
-- @treturn number|nil rr_code si numérique, nil sinon ("unknown"/vide).
parse_strip_resp = (resp) ->
  return nil unless resp and resp ~= ""
  id = resp\match "^(%d+)"
  return tonumber(id) if id
  nil

--- Retourne le rr_code à stripper pour un nom de question via une requête
-- au MAC learner. Mirroir exact de get_vlan, préfixe "strip:".
-- @tparam string name Nom de domaine cible
-- @treturn number|nil rr_code observé, ou nil si inconnu
strip_target = (name) ->
  return nil unless name and name ~= "" and name ~= "unknown"

  resp = query "strip:" .. name .. "\n"
  return nil unless resp

  parse_strip_resp resp

{ :get_mac, :get_vlan, :mac_from_eui64, :strip_target, :parse_strip_resp, :query }
