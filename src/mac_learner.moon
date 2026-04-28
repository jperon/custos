-- src/mac_learner.moon
-- Worker MAC Learner : table IP → MAC en mémoire avec TTL.
--
-- Sources  : messages binaires 22 octets (ip16 + mac6) via pipe (Q0 → learner)
-- Clients  : requêtes texte ligne par ligne via socket Unix SOCK_STREAM
--            "ip_str\n" → "aa:bb:cc:dd:ee:ff\n" ou "unknown\n"
--
-- Le worker tourne en boucle avec poll() pour multiplexer :
--   • la lecture du pipe de learn (non-bloquant)
--   • l'acceptation de connexions de requête
-- Purge périodique des entrées expirées (~60 s).

{ :ffi, :libc } = require "ffi_defs"
_cfg = require "config"
-- Fallbacks pour compatibilité avec d'anciennes versions de config.lua
-- (déploiements partiels où MAC_LEARNER_* n'est pas encore exporté).
MAC_LEARNER_QUERY_SOCK     = _cfg.MAC_LEARNER_QUERY_SOCK     or "/var/run/custos/mac_query.sock"
MAC_LEARNER_LEARN_MSG_SIZE = _cfg.MAC_LEARNER_LEARN_MSG_SIZE or 22
MAC_LEARNER_ENTRY_TTL      = _cfg.MAC_LEARNER_ENTRY_TTL      or 300
{ :log_info, :log_warn } = require "log"

bit    = require "bit"

AF_UNIX     = 1
SOCK_STREAM = 1
POLLIN      = 1
AF_INET6    = 10

-- ── Table en mémoire ─────────────────────────────────────────────
-- { ip_str → { mac, expires } }
-- indice 1 = MAC textuelle ; indice 2 = expiration epoch
mac_table = {}

-- ── Utilitaires ──────────────────────────────────────────────────

--- Convertit 16 octets bruts (format IPC) en adresse IP textuelle.
-- IPv4 : octets 1-4 significatifs, octets 5-16 nuls.
-- IPv6 : les 16 octets sont l'adresse complète.
-- @tparam string ip16 Chaîne de 16 octets
-- @treturn string Adresse IP textuelle (ex : "192.168.1.5" ou "fd00::1")
ip16_to_str = (ip16) ->
  is_ipv4 = true
  for i = 5, 16
    if ip16\byte(i) ~= 0
      is_ipv4 = false
      break
  if is_ipv4
    "#{ip16\byte 1}.#{ip16\byte 2}.#{ip16\byte 3}.#{ip16\byte 4}"
  else
    buf = ffi.new "uint8_t[16]"
    for i = 0, 15
      buf[i] = ip16\byte(i + 1)
    ntop = ffi.new "char[46]"
    libc.inet_ntop AF_INET6, buf, ntop, 46
    ffi.string ntop

-- ── Traitement des messages de learn ─────────────────────────────

--- Traite un message binaire de learn reçu depuis le pipe.
-- Ignore les messages avec MAC nulle (client inconnu de Q0).
-- @tparam string msg MAC_LEARNER_LEARN_MSG_SIZE octets (ip16 + mac6)
process_learn = (msg) ->
  return if #msg < MAC_LEARNER_LEARN_MSG_SIZE
  ip16    = msg\sub 1, 16
  mac_raw = msg\sub 17, 22

  -- Ignore les MACs toutes à zéro (nfq_get_packet_hw n'a rien retourné)
  all_zero = true
  for i = 1, 6
    if mac_raw\byte(i) ~= 0
      all_zero = false
      break
  return if all_zero

  ip_str  = ip16_to_str ip16
  mac_str = string.format "%02x:%02x:%02x:%02x:%02x:%02x",
    mac_raw\byte(1), mac_raw\byte(2), mac_raw\byte(3),
    mac_raw\byte(4), mac_raw\byte(5), mac_raw\byte(6)

  mac_table[ip_str] = { mac_str, os.time! + MAC_LEARNER_ENTRY_TTL }

-- ── Gestion des requêtes ──────────────────────────────────────────

--- Traite une connexion de requête : reçoit "ip\n", répond "mac\n" ou "unknown\n".
-- Ferme le fd à la fin.
-- @tparam number client_fd fd de la connexion cliente
handle_query = (client_fd) ->
  buf = ffi.new "char[64]"
  n = libc.recv client_fd, buf, 63, 0
  if n <= 0
    libc.close client_fd
    return

  req    = ffi.string buf, n
  ip_str = req\match "^([^\n\r]+)"
  resp   = "unknown\n"

  if ip_str
    now   = os.time!
    entry = mac_table[ip_str]
    if entry
      if now <= entry[2]
        resp = entry[1] .. "\n"
      else
        mac_table[ip_str] = nil   -- purge paresseuse

  libc.send client_fd, resp, #resp, 0
  libc.close client_fd

-- ── Socket Unix serveur ───────────────────────────────────────────

--- Crée et lie le socket Unix SOCK_STREAM pour les requêtes.
-- Supprime d'abord toute socket fantôme (crash précédent).
-- @tparam string path Chemin du fichier socket
-- @treturn number fd du socket serveur, ou -1 en cas d'erreur
create_server = (path) ->
  libc.unlink path

  sock = libc.socket AF_UNIX, SOCK_STREAM, 0
  return -1 if sock < 0

  addr = ffi.new "struct sockaddr_un"
  addr.sun_family = AF_UNIX
  ffi.copy addr.sun_path, path

  -- addrlen = offsetof(sun_path) + strlen(path) + 1
  addr_len = ffi.offsetof("struct sockaddr_un", "sun_path") + #path + 1

  if libc.bind(sock, ffi.cast("struct sockaddr*", addr), addr_len) ~= 0
    libc.close sock
    return -1

  if libc.listen(sock, 8) ~= 0
    libc.close sock
    return -1

  sock

-- ── Boucle principale ─────────────────────────────────────────────

--- Démarre le worker MAC Learner.
-- Lit les associations IP→MAC depuis le pipe de learn,
-- et répond aux requêtes texte via le socket Unix.
-- @tparam number learn_rfd fd de lecture du pipe de learn (Q0 → learner)
run = (learn_rfd) ->
  query_sock = create_server MAC_LEARNER_QUERY_SOCK
  if query_sock < 0
    log_warn { action: "mac_learner_socket_failed", path: MAC_LEARNER_QUERY_SOCK }
    return

  log_info { action: "mac_learner_start", sock: MAC_LEARNER_QUERY_SOCK }

  -- poll fds : [0] = pipe de learn, [1] = socket de requêtes
  pfds = ffi.new "struct pollfd[2]"
  pfds[0].fd     = learn_rfd
  pfds[0].events = POLLIN
  pfds[1].fd     = query_sock
  pfds[1].events = POLLIN

  learn_buf  = ffi.new "uint8_t[?]", MAC_LEARNER_LEARN_MSG_SIZE
  purge_tick = 0

  while true
    libc.poll pfds, 2, 1000   -- timeout 1 s ; on ne teste pas rc (purge quand même)

    -- Pipe de learn : draine tous les messages disponibles (non-bloquant)
    if bit.band(pfds[0].revents, POLLIN) ~= 0
      while true
        n = libc.read learn_rfd, learn_buf, MAC_LEARNER_LEARN_MSG_SIZE
        break if n <= 0
        if n == MAC_LEARNER_LEARN_MSG_SIZE
          process_learn ffi.string(learn_buf, MAC_LEARNER_LEARN_MSG_SIZE)

    -- Socket de requêtes : accepte et traite une connexion par itération
    if bit.band(pfds[1].revents, POLLIN) ~= 0
      client_fd = libc.accept query_sock, nil, nil
      handle_query client_fd if client_fd >= 0

    -- Purge périodique (~toutes les 60 itérations ≈ 60 s)
    purge_tick += 1
    if purge_tick >= 60
      purge_tick = 0
      now = os.time!
      for ip, entry in pairs mac_table
        mac_table[ip] = nil if now > entry[2]

{ :run }
