-- src/worker_q4.moon
-- Worker Q4 : apprentissage MAC ← IP depuis une NFQUEUE rate-limitée.
--
-- Rôle :
--  - Écoute la queue NFQUEUE `QUEUE_MAC_LEARN` (trafic IPv4/IPv6 bridgé).
--  - Pour chaque paquet : extrait la MAC source via `get_l2(nfad)` et
--    l'IP source depuis la charge utile (IP header). Si la MAC est connue,
--    on enregistre l'association IP→MAC dans une table mémoire avec TTL.
--  - Expose un socket Unix (MAC_LEARNER_QUERY_SOCK) pour répondre aux
--    requêtes synchrones des autres workers : "ip\n" → "aa:bb:cc:dd:ee:ff\n"
--
-- Comportement NFQUEUE :
--  - Mode : copie complète (payload + métadonnées)
--  - Verdict : toujours NF_ACCEPT (nous n'influençons pas le forwarding)
--  - Le callback met à jour la table mac_table et retourne 0.
--
-- La boucle multiplexe : [netlink fd NFQUEUE] + [socket Unix query] via poll().
-- Purge périodique des entrées expirées (~60 s).
--
-- Note : ce worker remplace l'ancien pipe Q0→learner : Q0 n'envoie plus de
-- messages d'apprentissage. Le learner est la source unique pour IP→MAC.

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :QUEUE_MAC_LEARN, :MAC_LEARNER_QUERY_SOCK, :MAC_LEARNER_ENTRY_TTL } = require "config"
{ :get_l2 } = require "parse/ethernet"
{ :log_info, :log_warn, :log_debug } = require "log"

bit = require "bit"

-- Constantes utiles
AF_UNIX     = 1
SOCK_STREAM = 1
POLLIN      = 1

-- Taille buffer lecture netlink (suffisante > MTU + overhead)
READ_BUF_SIZE = 65536

-- Table en mémoire : { ip_str -> { mac = "aa:bb:..", expires = ts } }
mac_table = {}

--- Convertit un pointeur payload (unsigned char*) en chaîne IP source.
-- Supporte IPv4 et IPv6 (lecture minimale sans validations exhaustives).
-- @tparam const unsigned char* p Payload pointer (IP header starts here)
-- @tparam number len Longueur du payload
-- @treturn string|nil ip textuelle ou nil si non déterminable
payload_src_ip = (p, len) ->
  return nil unless p and len and len > 0
  ver = bit.rshift(p[0], 4)
  if ver == 4
    -- IPv4 : src at offset 12 (requires >= 20)
    return nil if len < 20
    return string.format "%d.%d.%d.%d", p[12], p[13], p[14], p[15]
  else if ver == 6
    -- IPv6 : src at offset 8 (16 octets) (requires >= 40)
    return nil if len < 40
    -- copier 16 octets dans un buffer temporaire puis inet_ntop
    buf = ffi.new "uint8_t[16]"
    for i = 0, 15
      buf[i] = p[8 + i]
    ntop = ffi.new "char[46]"
    libc.inet_ntop 10, buf, ntop, 46    -- AF_INET6 = 10 ; import via config not nécessaire
    ffi.string ntop
  else
    nil

--- Met à jour la table mac_table pour une IP donnée.
-- @tparam string ip_str Adresse IP textuelle
-- @tparam string mac_raw 6-octets raw string de la MAC source
update_mac_table = (ip_str, mac_raw) ->
  return unless ip_str and ip_str ~= "" and mac_raw and #mac_raw == 6
  mac_str = string.format "%02x:%02x:%02x:%02x:%02x:%02x",
    mac_raw\byte(1), mac_raw\byte(2), mac_raw\byte(3),
    mac_raw\byte(4), mac_raw\byte(5), mac_raw\byte(6)
  mac_table[ip_str] = { mac: mac_str, expires: os.time! + MAC_LEARNER_ENTRY_TTL }
  log_debug { action: "learned_ip_mac", ip: ip_str, mac: mac_str }

--- Traite un paquet NFQUEUE : extrait L2, payload, IP source et met à jour table.
-- @tparam cdata nfad nfq_data* fourni par libnetfilter_queue
process_nfq_packet = (nfad) ->
  -- Extraire L2 depuis les métadonnées
  l2 = get_l2 nfad
  -- Lecture payload
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  if payload_len <= 0
    -- Rien à faire (pas d'IP payload)
    return
  p = ffi.cast "const uint8_t*", payload_ptr[0]
  -- Déduire l'IP source depuis le payload raw
  ip_str = payload_src_ip p, tonumber(payload_len)
  if not ip_str
    -- Impossible de déduire l'IP ; on logue en DEBUG pour enquête
    log_debug { action: "learn_skip_no_ip", mac_src: l2.mac_src, in_ifindex: l2.in_ifindex }
    return
  -- Si la MAC source est connue, on l'enregistre
  if l2.mac_src and l2.mac_src ~= "unknown"
    update_mac_table ip_str, l2.mac_raw
  else
    -- MAC inconnue : log au niveau debug (pas de WARN ici pour éviter bruit)
    log_debug { action: "learn_missing_mac", ip: ip_str, in_ifindex: l2.in_ifindex }

--- Crée et bind le socket Unix pour les requêtes de consultation.
-- Supprime toute socket fantôme avant bind.
-- @tparam string path Chemin du fichier socket
-- @treturn number fd du socket serveur, ou -1 en cas d'erreur
create_query_server = (path) ->
  libc.unlink path
  sock = libc.socket AF_UNIX, SOCK_STREAM, 0
  return -1 if sock < 0

  addr = ffi.new "struct sockaddr_un"
  addr.sun_family = AF_UNIX
  ffi.copy addr.sun_path, path
  addr_len = ffi.offsetof("struct sockaddr_un", "sun_path") + #path + 1

  if libc.bind(sock, ffi.cast("struct sockaddr*", addr), addr_len) ~= 0
    libc.close sock
    return -1

  if libc.listen(sock, 8) ~= 0
    libc.close sock
    return -1

  sock

--- Accepte et traite une connexion client de requête (bloquant court).
-- Reçoit "ip\n" et répond "mac\n" ou "unknown\n".
-- @tparam number client_fd fd de la connexion
handle_query = (client_fd) ->
  buf = ffi.new "char[64]"
  n = libc.recv client_fd, buf, 63, 0
  if n <= 0
    libc.close client_fd
    return
  req = ffi.string buf, n
  ip_str = req\match "^([^\n\r]+)"
  resp = "unknown\n"
  if ip_str
    entry = mac_table[ip_str]
    if entry and os.time! <= entry.expires
      resp = entry.mac .. "\n"
    else
      -- purge paresseuse
      mac_table[ip_str] = nil if entry
  libc.send client_fd, resp, #resp, 0
  libc.close client_fd

--- Démarre le worker Q4 : ouvre la NFQUEUE et le socket query, boucle poll().
-- Ne prend aucun argument : forké directement par `main.moon`.
run = ->
  -- Création socket query
  query_sock = create_query_server MAC_LEARNER_QUERY_SOCK
  if query_sock < 0
    log_warn { action: "mac_learner_socket_failed", path: MAC_LEARNER_QUERY_SOCK }
    return

  -- Ouverture NFQUEUE
  h = libnfq.nfq_open!
  error "nfq_open() échoué" if h == nil

  -- Bind PF (IPv4/IPv6/BRIDGE)
  libnfq.nfq_bind_pf h, 2     -- AF_INET
  libnfq.nfq_bind_pf h, 10    -- AF_INET6
  libnfq.nfq_bind_pf h, 7     -- AF_BRIDGE (const symbolic in nfq_loop)

  -- Création queue et wrapper callback
  qh_box = ffi.new "nfq_q_handle*[1]"

  -- Process packet wrapper (appelé depuis le C callback via pcall)
  process_packet_wrap = (nfad) ->
    ok, err = pcall process_nfq_packet, nfad
    unless ok
      log_warn { action: "nfq_process_failed", err: tostring err }

  c_callback = ffi.cast "nfq_callback", (qh, nfmsg, nfad, data) ->
    -- Extraction id paquet
    raw_hdr = libnfq.nfq_get_msg_packet_hdr nfad
    pkt_id = libc.ntohl raw_hdr.packet_id

    -- Appel traitement (protégé)
    pcall process_packet_wrap, nfad

    -- Toujours accepter le paquet (nous n'altérons pas le paquet)
    libnfq.nfq_set_verdict qh_box[0], pkt_id, 1, 0, nil   -- NF_ACCEPT = 1

    0  -- succès pour le callback C

  qh = libnfq.nfq_create_queue h, QUEUE_MAC_LEARN, c_callback, nil
  error "nfq_create_queue(#{QUEUE_MAC_LEARN}) échoué" if qh == nil
  qh_box[0] = qh

  -- Copie complète du paquet
  libnfq.nfq_set_mode qh, 2, READ_BUF_SIZE    -- NFQNL_COPY_PACKET = 2

  fd = libnfq.nfq_fd h
  buf = ffi.new "char[?]", READ_BUF_SIZE

  log_info { action: "worker_q4_start", queue: QUEUE_MAC_LEARN, sock: MAC_LEARNER_QUERY_SOCK }

  -- poll fds : [0] = netlink fd (NFQUEUE), [1] = query socket
  pfds = ffi.new "struct pollfd[2]"
  pfds[0].fd = fd
  pfds[0].events = POLLIN
  pfds[1].fd = query_sock
  pfds[1].events = POLLIN

  purge_tick = 0

  while true
    -- poll timeout 1000ms
    libc.poll pfds, 2, 1000

    -- Données NFQUEUE : lire et dispatcher à libnfq
    if bit.band(pfds[0].revents, POLLIN) ~= 0
      rv = libc.read fd, buf, READ_BUF_SIZE
      if rv > 0
        libnfq.nfq_handle_packet h, buf, tonumber rv

    -- Requête de consultation : accepte & traite
    if bit.band(pfds[1].revents, POLLIN) ~= 0
      client_fd = libc.accept query_sock, nil, nil
      handle_query client_fd if client_fd >= 0

    -- Purge périodique (~60s)
    purge_tick += 1
    if purge_tick >= 60
      purge_tick = 0
      now = os.time!
      for ip, entry in pairs mac_table
        mac_table[ip] = nil if now > entry.expires

  -- Cleanup (jamais atteint normalement)
  libnfq.nfq_destroy_queue qh
  libnfq.nfq_close h
  c_callback\free!

{ :run }
