-- src/mac_learner_ipc.moon
-- Client IPC pour le worker MAC Learner.
--
-- Deux opérations :
--   learn  : envoi non-bloquant d'une association (IP → MAC) via pipe binaire
--   get_mac: requête synchrone via socket Unix SOCK_STREAM (protocole texte ligne)
--
-- Protocole learn (pipe, 22 octets atomiques) :
--   [0..15] : IP source (IPv4 : 4 octets + 12 zéros ; IPv6 : 16 octets)
--   [16..21]: MAC source (6 octets bruts)
--
-- Protocole query (Unix SOCK_STREAM, texte) :
--   → envoi   : "<ip_str>\n"
--   ← réponse : "<mac_str>\n"  ou  "unknown\n"

{ :ffi, :libc } = require "ffi_defs"
{ :MAC_LEARNER_QUERY_SOCK } = require "config"
{ :log_warn } = require "log"

AF_UNIX     = 1
SOCK_STREAM = 1

-- ── Learn (Q0 → MAC learner via pipe) ────────────────────────────

--- Encode une association IP→MAC en message binaire de 22 octets.
-- @tparam string ip_raw  4 octets (IPv4) ou 16 octets (IPv6) bruts
-- @tparam string mac_raw 6 octets bruts de la MAC source
-- @treturn string Message binaire de 22 octets
encode_learn = (ip_raw, mac_raw) ->
  buf = ffi.new "uint8_t[22]"
  -- IP dans les 16 premiers octets (IPv4 : 4 octets, les 12 suivants restent à 0x00)
  for i = 1, #ip_raw
    buf[i - 1] = ip_raw\byte i
  -- MAC dans les 6 octets suivants (offset 16)
  for i = 1, 6
    buf[15 + i] = mac_raw\byte i
  ffi.string buf, 22

--- Envoie une association IP→MAC au MAC learner via le pipe de learn.
-- Écriture non-bloquante (O_NONBLOCK sur le pipe) : perte silencieuse si le
-- pipe est plein — acceptable, le learner sera alimenté au prochain paquet.
-- @tparam number pipe_wfd fd d'écriture du pipe
-- @tparam string ip_raw   4 ou 16 octets bruts de l'IP source
-- @tparam string mac_raw  6 octets bruts de la MAC source
-- @treturn boolean true si l'écriture a réussi
learn = (pipe_wfd, ip_raw, mac_raw) ->
  return false unless pipe_wfd and ip_raw and mac_raw
  return false unless #mac_raw == 6
  msg = encode_learn ip_raw, mac_raw
  n = libc.write pipe_wfd, msg, #msg
  n == #msg

-- ── Query (AUTH / Q2 → MAC learner via socket Unix) ───────────────

--- Retourne la MAC associée à une IP via une requête au MAC learner.
-- Connexion synchrone sur socket Unix SOCK_STREAM : approprié pour AUTH
-- (une requête par connexion entrante) et pour Q2 (SYNs rate-limités par nft).
-- @tparam string ip_str Adresse IP sous forme de chaîne
-- @treturn string MAC "aa:bb:cc:dd:ee:ff" ou "unknown"
get_mac = (ip_str) ->
  return "unknown" unless ip_str and ip_str ~= "" and ip_str ~= "unknown"

  sock = libc.socket AF_UNIX, SOCK_STREAM, 0
  return "unknown" if sock < 0

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

{ :learn, :get_mac }
