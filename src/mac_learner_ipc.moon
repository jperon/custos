-- src/mac_learner_ipc.moon
-- Client IPC pour le worker MAC Learner (query-only).
--
-- Fourni uniquement la fonction `get_mac(ip_str)` qui interroge le socket
-- Unix du learner et retourne la MAC textuelle ou "unknown".
--
-- Anciennement ce module fournissait aussi `learn()` (Q0 → learner via pipe).
-- Aujourd'hui l'apprentissage se fait via le worker mac_learner (socket Unix).
-- `learn()` n'est plus nécessaire ici.

{ :ffi, :libc } = require "ffi_defs"
{ :MAC_LEARNER_QUERY_SOCK } = require "config"
{ :log_warn } = require "log"

AF_UNIX     = 1
AF_INET6    = 10
SOCK_STREAM = 1

bit = require "bit"

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
  string.format "%02x:%02x:%02x:%02x:%02x:%02x",
    b0, buf[9], buf[10], buf[13], buf[14], buf[15]

--- Retourne la MAC associée à une IP via une requête au MAC learner.
-- Connexion synchrone sur socket Unix SOCK_STREAM : approprié pour AUTH
-- (une requête par connexion entrante) et pour Q2 (SYNs rate-limités par nft).
-- @tparam string ip_str Adresse IP sous forme de chaîne
-- @treturn string MAC "aa:bb:cc:dd:ee:ff" ou "unknown"
get_mac = (ip_str) ->
  return "unknown" unless ip_str and ip_str ~= "" and ip_str ~= "unknown"

  sock = libc.socket AF_UNIX, SOCK_STREAM, 0
  unless sock >= 0
    log_warn { action: "mac_ipc_socket_failed", errno: tonumber(ffi.C.__errno_location()[0]) }
    return mac_from_eui64(ip_str) or "unknown"

  addr = ffi.new "struct sockaddr_un"
  addr.sun_family = AF_UNIX
  ffi.copy addr.sun_path, MAC_LEARNER_QUERY_SOCK
  -- addrlen = offset de sun_path + longueur du chemin + '\0'
  addr_len = ffi.offsetof("struct sockaddr_un", "sun_path") + #MAC_LEARNER_QUERY_SOCK + 1

  if libc.connect(sock, ffi.cast("struct sockaddr*", addr), addr_len) ~= 0
    libc.close sock
    return mac_from_eui64(ip_str) or "unknown"

  -- Envoi : "ip_str\n"
  req = ip_str .. "\n"
  libc.send sock, req, #req, 0

  -- Lecture de la réponse : "aa:bb:cc:dd:ee:ff\n" (18 octets) ou "unknown\n" (8)
  buf = ffi.new "char[64]"
  n = libc.recv sock, buf, 63, 0
  libc.close sock

  return "unknown" if n <= 0

  resp = ffi.string buf, n
  -- Extrait la MAC (format "xx:xx:xx:xx:xx:xx") ou "unknown"
  mac = resp\match "^([0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f])"
  return mac if mac

  -- Fallback EUI-64 : si le learner ne connaît pas cette adresse IPv6 mais
  -- qu'elle encode une MAC EUI-64, on la dérive directement sans apprentissage.
  mac = mac_from_eui64 ip_str
  return mac if mac

  "unknown"

{ :get_mac, :mac_from_eui64 }
