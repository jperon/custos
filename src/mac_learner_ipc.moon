-- src/mac_learner_ipc.moon
-- Client IPC pour le worker MAC Learner (query-only).
--
-- Fourni uniquement la fonction `get_mac(ip_str)` qui interroge le socket
-- Unix du learner et retourne la MAC textuelle ou "unknown".
--
-- Anciennement ce module fournissait aussi `learn()` (Q0 → learner via pipe).
-- Avec worker_q4 (NFQUEUE) l'apprentissage se fait directement depuis la queue,
-- donc `learn()` n'est plus nécessaire ici.

{ :ffi, :libc } = require "ffi_defs"
{ :MAC_LEARNER_QUERY_SOCK } = require "config"
{ :log_warn } = require "log"

AF_UNIX     = 1
SOCK_STREAM = 1

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
    return "unknown"

  addr = ffi.new "struct sockaddr_un"
  addr.sun_family = AF_UNIX
  ffi.copy addr.sun_path, MAC_LEARNER_QUERY_SOCK
  -- addrlen = taille fixe de sun_family (2) + longueur du chemin + '\0'
  addr_len = 2 + #MAC_LEARNER_QUERY_SOCK + 1

  if libc.connect(sock, ffi.cast("struct sockaddr*", addr), addr_len) ~= 0
    libc.close sock
    return "unknown"

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
  mac or "unknown"

{ :get_mac }
