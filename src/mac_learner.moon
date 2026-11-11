-- src/mac_learner.moon
-- Worker MAC Learner : table IP → MAC en mémoire avec TTL.
--
-- Sources  : messages binaires 22 octets (ip16 + mac6) via pipe (question → learner)
-- Clients  : requêtes texte ligne par ligne via socket Unix SOCK_STREAM
--            "ip_str\n" → "aa:bb:cc:dd:ee:ff\n" ou "unknown\n"
--
-- Sondage actif (event-driven) :
--   Si l'IP est inconnue, mac_prober.send_probe() envoie un ARP request ou un
--   Neighbor Solicitation sans bloquer. Le fd client est conservé ouvert dans
--   pending_queries. La boucle poll principale surveille arp_fd et ip6_fd ;
--   dès qu'une réponse arrive (ou au timeout PROBE_TIMEOUT_MS), tous les clients
--   en attente pour cette IP sont notifiés. Aucun blocage quelle que soit la charge.
--
-- Boucle poll (4 fds max) :
--   [0] pipe learn       — messages ip16+mac6 depuis question/arp_sniffer/auth_queue
--   [1] socket Unix      — connexions de requête MAC
--   [2] prober.arp_fd    — ARP replies (IPv4, si prober disponible)
--   [3] prober.ip6_fd    — Neighbor Advertisements (IPv6, si prober IPv6 dispo)
--
-- Timeout poll adaptatif : 20 ms quand des probes sont en vol, 1 s sinon.
-- Purge périodique basée sur os.time() (insensible au timeout adaptatif).

{ :ffi, :libc } = require "ffi_defs"
mac_prober = require "mac_prober"
strip_codec = require "strip_codec"
config = require "config"
{ :log_info, :log_warn, :log_debug } = require "log"
{ :enrich_session_ip } = require "auth.sessions"
{ :ip2s } = require "ipparse.l3.ip"
{ :mac2s } = require "packet_utils"
{ :purge_pending } = require "ipc"
mac_cfg = config.mac_learner or {}
auth_cfg = config.auth or {}

-- Délai maximum (ms) avant de répondre "unknown" aux clients en attente d'un probe.
PROBE_TIMEOUT_MS = 200
-- Durée (s) du cache négatif : évite de re-sonder une IP sans réponse.
NEGATIVE_TTL     = 30
-- Intervalle (s) de purge des entrées expirées de mac_table et negative_cache.
PURGE_INTERVAL   = 60

bit = require "bit"

AF_UNIX     = 1
SOCK_STREAM = 1
POLLIN      = 1

-- Timeout des recv de requête : un client qui se connecte sans jamais écrire
-- ne doit pas figer l'unique boucle poll du learner (qui sert alors tous les
-- get_mac/get_vlan/strip_target).
SOL_SOCKET   = 1
SO_RCVTIMEO  = 20
QUERY_RECV_TIMEOUT_S = 0.2

--- Borne le temps d'attente d'un recv bloquant sur un fd de connexion.
-- Best-effort : un mock de libc en test peut ne pas exposer setsockopt.
-- @tparam number fd   Descripteur de socket
-- @tparam number secs Délai maximal (secondes, fractions acceptées)
set_recv_timeout = (fd, secs) ->
  pcall ->
    tv = ffi.new "struct timeval"
    tv.tv_sec  = math.floor secs
    tv.tv_usec = math.floor (secs - math.floor(secs)) * 1e6
    libc.setsockopt fd, SOL_SOCKET, SO_RCVTIMEO, tv, ffi.sizeof tv

sh_quote = (s) ->
  "'" .. tostring(s)\gsub("'", "'\"'\"'") .. "'"

ensure_parent_dir = (path) ->
  parent = tostring(path)\match "^(.*)/[^/]+$"
  return true unless parent and parent != ""
  ret = os.execute "mkdir -p #{sh_quote(parent)}"
  ret == 0 or ret == true

--- Répond "unknown\n" à un client et ferme sa connexion.
-- @tparam number fd Descripteur de la connexion cliente
reply_unknown = (fd) ->
  libc.send fd, "unknown\n", 8, 0
  libc.close fd

-- ── Tables en mémoire ───────────────────────────────────────────
-- mac_table       : { ip_str → { mac_str, expires_epoch } }
-- negative_cache  : { ip_str → expires_epoch }
-- pending_queries : { ip_str → { {client_fd, expiry_ms}, ... } }
-- prober          : contexte mac_prober, initialisé dans run()
mac_table       = {}
negative_cache  = {}
pending_queries = {}
prober          = nil
-- vlan_table : { ip_str → { vlan_id, expires_epoch } }, alimenté par worker_doh_vlan.
-- vlan_id == 0 signifie « untagged observé » (distinct de l'absence d'entrée).
vlan_table      = {}
-- strip_table : { hash8 → { rr_code, expires_epoch } }, alimenté par worker_responses
-- (cibles CNAME de chaînes buggées). Clé = hash FNV-1a du nom (cf. strip_codec).
strip_table     = {}
STRIP_TTL       = mac_cfg.strip_ttl or 120

-- ── Utilitaires ──────────────────────────────────────────────────

--- Convertit 16 octets bruts (format IPC) en adresse IP textuelle.
-- IPv4 : octets 1-4 significatifs, octets 5-16 nuls.
-- IPv6 : les 16 octets sont l'adresse complète.
-- Utilise ip2s pour garantir la cohérence avec le reste du codebase.
-- @tparam string ip16 Chaîne de 16 octets
-- @treturn string Adresse IP textuelle (ex : "192.168.1.5" ou "fd00::1")
ip16_to_str = (ip16) ->
  is_ipv4 = true
  for i = 5, 16
    if ip16\byte(i) ~= 0
      is_ipv4 = false
      break
  if is_ipv4
    ip2s ip16\sub 1, 4
  else
    ip2s ip16

-- ── Apprentissage centralisé ─────────────────────────────────────

--- Stocke l'association ip_str→mac_str dans mac_table et notifie
-- immédiatement tous les clients en attente d'un probe pour cette IP.
-- Point d'entrée unique pour tout apprentissage (pipe learn ET probe reply).
-- @tparam string ip_str   Adresse IP (clé de mac_table et pending_queries)
-- @tparam string mac_str  Adresse MAC "aa:bb:cc:dd:ee:ff"
learn_mac = (ip_str, mac_str) ->
  existing = mac_table[ip_str]
  is_new = not existing or existing[1] != mac_str
  mac_table[ip_str] = { mac_str, os.time! + (mac_cfg.entry_ttl or 300) }
  if is_new
    ok, enriched = pcall enrich_session_ip, mac_str, ip_str, auth_cfg.sessions_file
    if ok and enriched
      log_info -> { action: "session_enriched", ip: ip_str, mac: mac_str }
  waiters = pending_queries[ip_str]
  return unless waiters
  resp = mac_str .. "\n"
  for _, w in ipairs waiters
    libc.send w[1], resp, #resp, 0
    libc.close w[1]
  pending_queries[ip_str] = nil

-- ── Traitement des messages de learn ─────────────────────────────

--- Traite un message binaire de learn reçu depuis le pipe.
-- Ignore les messages avec MAC nulle (client inconnu de question).
-- @tparam string msg MAC_LEARNER_LEARN_MSG_SIZE octets (ip16 + mac6)
process_learn = (msg) ->
  msg_size = mac_cfg.learn_msg_size or 22
  return if #msg < msg_size
  ip16    = msg\sub 1, 16
  mac_raw = msg\sub 17, 22

  all_zero = true
  for i = 1, 6
    if mac_raw\byte(i) ~= 0
      all_zero = false
      break
  return if all_zero

  ip_str  = ip16_to_str ip16
  mac_str = mac2s mac_raw

  learn_mac ip_str, mac_str

-- ── Apprentissage VLAN (worker_doh_vlan) ─────────────────────────

--- Traite un message binaire de learn VLAN reçu depuis le pipe vlan_learn.
-- Format : ip16 (16 octets) + vlan uint16 big-endian (2 octets) = 18 octets.
-- vlan == 0 (untagged) est mémorisé tel quel et écrase toute entrée antérieure :
-- indispensable à l'anti-spoofing (cf. AGENTS.md « from_vlan en DoH »).
-- @tparam string msg 18 octets (ip16 + vlan16)
process_vlan_learn = (msg) ->
  return if #msg < 18
  ip16 = msg\sub 1, 16
  vlan = msg\byte(17) * 256 + msg\byte(18)
  ip_str = ip16_to_str ip16
  vlan_table[ip_str] = { vlan, os.time! + (mac_cfg.entry_ttl or 300) }

--- Recherche le VLAN observé pour une IP (helper de test + requête socket).
-- @tparam string ip_str Adresse IP textuelle
-- @treturn number|nil VLAN ID (0 = untagged) si entrée valide, nil sinon
vlan_lookup = (ip_str) ->
  entry = vlan_table[ip_str]
  return nil unless entry
  if os.time! <= entry[2]
    entry[1]
  else
    vlan_table[ip_str] = nil
    nil

-- ── Apprentissage des cibles de strip CNAME (worker_responses) ───

--- Traite un message de learn de cible de strip (10 octets, cf. strip_codec).
-- @tparam string msg 10 octets (hash8 + rr_code uint16 BE)
process_strip_learn = (msg) ->
  hash8, rr_code = strip_codec.decode msg
  return unless hash8
  strip_table[hash8] = { rr_code, os.time! + STRIP_TTL }

--- Recherche le rr_code à stripper pour un nom de question.
-- @tparam string name Nom de domaine (insensible à la casse)
-- @treturn number|nil code DNS du type à stripper, ou nil si non cible/expiré.
strip_lookup = (name) ->
  hash8 = strip_codec.name_hash name
  entry = strip_table[hash8]
  return nil unless entry
  if os.time! <= entry[2]
    entry[1]
  else
    strip_table[hash8] = nil
    nil

-- ── Expiration des probes en attente ─────────────────────────────

--- Expire les requêtes en attente dont le probe dépasse PROBE_TIMEOUT_MS.
-- Répond "unknown\n" aux clients expirés, alimente le cache négatif.
expire_pending = ->
  now_ms    = mac_prober.get_ms!
  now_epoch = os.time!
  for ip_str, waiters in pairs pending_queries
    i = #waiters
    while i >= 1
      if now_ms > waiters[i][2]
        reply_unknown waiters[i][1]
        table.remove waiters, i
      i -= 1
    if #waiters == 0
      pending_queries[ip_str] = nil
      negative_cache[ip_str] = now_epoch + NEGATIVE_TTL

-- ── Gestion des requêtes ──────────────────────────────────────────

--- Tente d'enregistrer un client en attente de probe pour une IP inconnue.
-- Extrait de start_query pour être testable sans socket. Si un probe est déjà
-- en vol, le client rejoint la file sans nouvelle sonde ; si l'envoi échoue,
-- répond "unknown", ferme le fd et pose le cache négatif (sinon fuite de fd et
-- client bloqué côté mac_learner_ipc.get_mac).
-- @tparam table pending   Table pending_queries { ip → { {fd, expiry_ms}, … } }
-- @tparam table negative  Table negative_cache { ip → expires_epoch }
-- @tparam table prober_ctx Contexte mac_prober (passé à send_probe)
-- @tparam number client_fd Descripteur de la connexion cliente
-- @tparam string ip_str   Adresse IP demandée
-- @tparam number now      Epoch courant (secondes)
-- @tparam function get_ms Fonction retournant l'horloge monotone (ms)
-- @tparam function send_probe Fonction d'envoi de sonde (pcall-able)
-- @treturn string "pending" (fd gardé ouvert) | "joined" | "failed" (fd fermé)
probe_request = (pending, negative, prober_ctx, client_fd, ip_str, now, get_ms, send_probe) ->
  expiry_ms = get_ms! + PROBE_TIMEOUT_MS
  if pending[ip_str]
    -- Probe déjà en vol : rejoindre la file sans émettre de nouvelle sonde
    pending[ip_str][#pending[ip_str] + 1] = { client_fd, expiry_ms }
    return "joined"

  ok, sent = pcall send_probe, prober_ctx, ip_str
  if ok and sent
    pending[ip_str] = { { client_fd, expiry_ms } }
    return "pending"

  -- Envoi échoué : répondre immédiatement "unknown" et fermer, cache négatif
  negative[ip_str] = now + NEGATIVE_TTL
  reply_unknown client_fd
  "failed"

--- Traite une connexion de requête de façon non-bloquante.
-- Si la MAC est connue : répond et ferme immédiatement.
-- Si le cache négatif est actif : répond "unknown" et ferme.
-- Si inconnue et probe possible : envoie la sonde, conserve client_fd
--   ouvert dans pending_queries (réponse asynchrone par learn_mac /
--   expire_pending). Si un probe est déjà en vol pour cette IP, le client
--   rejoint la file d'attente sans émettre de sonde supplémentaire.
-- @tparam number client_fd fd de la connexion cliente
start_query = (client_fd) ->
  buf = ffi.new "char[64]"
  set_recv_timeout client_fd, QUERY_RECV_TIMEOUT_S
  n = libc.recv client_fd, buf, 63, 0
  if n <= 0
    libc.close client_fd
    return

  req    = ffi.string buf, n

  -- Requête VLAN : "vlan:<ip>\n" → "<id>\n" (0 = untagged observé) ou "unknown\n".
  -- Lecture seule de vlan_table (alimentée par worker_doh_vlan) ; pas de probe.
  vlan_ip = req\match "^vlan:([^\n\r]+)"
  if vlan_ip
    vid = vlan_lookup vlan_ip
    if vid
      resp = vid .. "\n"
      libc.send client_fd, resp, #resp, 0
      libc.close client_fd
    else
      reply_unknown client_fd
    return

  -- Requête strip : "strip:<name>\n" → "<rr_code>\n" ou "unknown\n".
  -- Lecture seule de strip_table (alimentée par worker_responses) ; pas de probe.
  strip_name = req\match "^strip:([^\n\r]+)"
  if strip_name
    rr = strip_lookup strip_name
    if rr
      resp = rr .. "\n"
      libc.send client_fd, resp, #resp, 0
      libc.close client_fd
    else
      reply_unknown client_fd
    return

  ip_str = req\match "^([^\n\r]+)"
  unless ip_str
    reply_unknown client_fd
    return

  now   = os.time!
  entry = mac_table[ip_str]
  if entry
    if now <= entry[2]
      resp = entry[1] .. "\n"
      libc.send client_fd, resp, #resp, 0
      libc.close client_fd
      return
    else
      mac_table[ip_str] = nil   -- expirée : purge paresseuse

  -- Cache négatif actif → répondre "unknown" sans sonder
  neg_exp = negative_cache[ip_str]
  if neg_exp and now <= neg_exp
    reply_unknown client_fd
    return

  -- Adresse inconnue : sondage asynchrone si prober disponible
  if prober
    probe_request pending_queries, negative_cache, prober, client_fd, ip_str,
      now, mac_prober.get_ms, mac_prober.send_probe
    return

  -- Pas de prober : répondre "unknown" directement
  reply_unknown client_fd

-- ── Socket Unix serveur ───────────────────────────────────────────

--- Crée et lie le socket Unix SOCK_STREAM pour les requêtes.
-- Supprime d'abord toute socket fantôme (crash précédent).
-- @tparam string path Chemin du fichier socket
-- @treturn number fd du socket serveur, ou -1 en cas d'erreur
create_server = (path) ->
  return -1 unless ensure_parent_dir path
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
-- Initialise le prober ARP/NS, ouvre le socket Unix, entre dans la boucle
-- poll sur jusqu'à 4 fds (pipe learn, query sock, arp_fd, ip6_fd).
-- @tparam number learn_rfd  fd de lecture du pipe de learn (question → learner)
-- @tparam string [ifname]   Nom de l'interface bridge (défaut : "br")
-- @tparam number [vlan_learn_rfd] fd de lecture du pipe vlan_learn (worker_doh_vlan → learner)
-- @tparam number [strip_learn_rfd] fd de lecture du pipe strip_learn (worker_responses → learner)
run = (learn_rfd, ifname, vlan_learn_rfd, strip_learn_rfd) ->
  ifname = ifname or "br"
  prober = mac_prober.init ifname
  if prober
    log_info -> { action: "mac_prober_ready", ifname: ifname,
      ns_enabled: prober.ip6_fd ~= nil }
  else
    log_warn -> { action: "mac_prober_disabled", ifname: ifname }

  query_sock_path = mac_cfg.query_sock or config.MAC_LEARNER_QUERY_SOCK or "/var/run/custos/mac_query.sock"
  query_sock = create_server query_sock_path
  if query_sock < 0
    errno = tonumber(ffi.C.__errno_location()[0])
    log_warn -> { action: "mac_learner_socket_failed", path: query_sock_path, errno: errno }
    return

  log_info -> { action: "mac_learner_start", sock: query_sock_path }

  -- Tableau pollfd[6] : [0] pipe learn, [1] query sock,
  --                     [2] arp_fd (opt.), [3] ip6_fd (opt.),
  --                     [vlan_idx] vlan_learn (opt., worker_doh_vlan),
  --                     [strip_idx] strip_learn (opt., worker_responses)
  pfds = ffi.new "struct pollfd[6]"
  pfds[0].fd     = learn_rfd
  pfds[0].events = POLLIN
  pfds[1].fd     = query_sock
  pfds[1].events = POLLIN
  nfds = 2

  if prober
    pfds[2].fd     = prober.arp_fd
    pfds[2].events = POLLIN
    nfds = 3
    if prober.ip6_fd
      pfds[3].fd     = prober.ip6_fd
      pfds[3].events = POLLIN
      nfds = 4

  -- Pipe vlan_learn (optionnel) : ajouté au prochain index libre.
  vlan_idx = -1
  if vlan_learn_rfd
    vlan_idx = nfds
    pfds[vlan_idx].fd     = vlan_learn_rfd
    pfds[vlan_idx].events = POLLIN
    nfds += 1

  -- Pipe strip_learn (optionnel) : ajouté au prochain index libre.
  strip_idx = -1
  if strip_learn_rfd
    strip_idx = nfds
    pfds[strip_idx].fd     = strip_learn_rfd
    pfds[strip_idx].events = POLLIN
    nfds += 1

  msg_size = mac_cfg.learn_msg_size or 22
  learn_buf  = ffi.new "uint8_t[?]", msg_size
  arp_buf    = ffi.new "uint8_t[512]"
  ipv6_buf   = ffi.new "uint8_t[2048]"
  vlan_buf   = ffi.new "uint8_t[18]"
  strip_buf  = ffi.new "uint8_t[?]", strip_codec.STRIP_MSG_SIZE
  last_purge = 0

  while true
    -- Timeout adaptatif : 20 ms si des probes sont en vol (pour expire_pending
    -- réactif), 1000 ms sinon (idle, économie CPU).
    poll_ms = if next(pending_queries) ~= nil then 20 else 1000
    libc.poll pfds, nfds, poll_ms

    -- [0] Pipe de learn : draine tous les messages disponibles (non-bloquant)
    -- Garde anti-corruption : un message incomplet (< msg_size) est ignoré
    -- mais ne doit PAS consommer le reste du message suivant.
    if bit.band(pfds[0].revents, POLLIN) ~= 0
      while true
        n = libc.read learn_rfd, learn_buf, msg_size
        break if n <= 0
        break if n < msg_size
        process_learn ffi.string(learn_buf, msg_size)

    -- [1] Socket de requêtes : une connexion par itération (accept non-bloquant)
    if bit.band(pfds[1].revents, POLLIN) ~= 0
      client_fd = libc.accept query_sock, nil, nil
      start_query client_fd if client_fd >= 0

    -- [2] ARP replies : apprend et notifie les clients en attente
    if nfds >= 3 and bit.band(pfds[2].revents, POLLIN) ~= 0
      n = libc.recv prober.arp_fd, arp_buf, 512, 0
      if n > 0
        raw = ffi.string arp_buf, n
        ip_str, mac_str = mac_prober.parse_arp_frame raw, n
        if ip_str and mac_str
          learn_mac ip_str, mac_str
          log_debug -> { action: "mac_learned_arp", ip: ip_str, mac: mac_str }

    -- [3] Neighbor Advertisements : apprend et notifie les clients en attente
    if nfds >= 4 and bit.band(pfds[3].revents, POLLIN) ~= 0
      n = libc.recv prober.ip6_fd, ipv6_buf, 2048, 0
      if n > 0
        raw = ffi.string ipv6_buf, n
        ip_str, mac_str = mac_prober.parse_na_frame raw, n
        if ip_str and mac_str
          learn_mac ip_str, mac_str
          log_debug -> { action: "mac_learned_na", ip: ip_str, mac: mac_str }

    -- [vlan_idx] Pipe vlan_learn : draine tous les messages (18 octets chacun)
    if vlan_idx >= 0 and bit.band(pfds[vlan_idx].revents, POLLIN) ~= 0
      while true
        n = libc.read vlan_learn_rfd, vlan_buf, 18
        break if n <= 0
        process_vlan_learn ffi.string(vlan_buf, 18) if n == 18

    -- [strip_idx] Pipe strip_learn : draine tous les messages (10 octets chacun)
    if strip_idx >= 0 and bit.band(pfds[strip_idx].revents, POLLIN) ~= 0
      while true
        n = libc.read strip_learn_rfd, strip_buf, strip_codec.STRIP_MSG_SIZE
        break if n <= 0
        process_strip_learn ffi.string(strip_buf, strip_codec.STRIP_MSG_SIZE) if n == strip_codec.STRIP_MSG_SIZE

    -- Expiration des probes dépassant PROBE_TIMEOUT_MS
    expire_pending! if next(pending_queries) ~= nil

    -- Purge périodique des transactions IPC en attente (défense en profondeur)
    purge_pending os.time if next(pending_queries) ~= nil

    -- Purge périodique (basée sur os.time(), insensible au poll_ms adaptatif)
    now_epoch = os.time!
    if now_epoch - last_purge >= PURGE_INTERVAL
      last_purge = now_epoch
      for ip, entry in pairs mac_table
        mac_table[ip] = nil if now_epoch > entry[2]
      for ip, exp in pairs negative_cache
        negative_cache[ip] = nil if now_epoch > exp
      for ip, entry in pairs vlan_table
        vlan_table[ip] = nil if now_epoch > entry[2]
      for h, entry in pairs strip_table
        strip_table[h] = nil if now_epoch > entry[2]

{ :run, :process_vlan_learn, :vlan_lookup, :process_strip_learn, :strip_lookup, :probe_request, :start_query }
