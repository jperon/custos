-- src/worker_q1.moon
-- Worker Q1 : traitement des réponses DNS (UDP/53 dst=LAN, src=resolver).
--
-- Pour chaque paquet :
--   1. Draine le pipe IPC (absorbe les tokens Q0 → table pending)
--   2. Parse L3/L4/L7 via parse/ndpi (IPv4 et IPv6)
--   3. Vérifie que la transaction (txid, dst_ip, dst_port) est dans pending
--      (dst_ip/dst_port de la réponse = src_ip/src_port de la question)
--   4. Si autorisée :
--        a. Parse les RR DNS de la réponse
--        b. Patch TTL de tous les RR → FORCED_TTL secondes
--        c. Recalcule checksums UDP (pseudo-header IPv4 ou IPv6) et IP (IPv4)
--        d. Ajoute les IPs A/AAAA dans les sets nft (timeout 2m)
--        e. Envoie le paquet modifié avec NF_ACCEPT + payload
--   5. Si non autorisée (réponse forgée ou question bloquée) : NF_DROP

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :QUEUE_RESPONSES, :DOCKER_MODE, :FORCED_TTL, :CLIENT_EXPIRY, :NEIGH_REFRESH_COOLDOWN } = require "config"
neigh = require "neigh"
ndpi = require "parse/ndpi"
{ :QTYPE } = ndpi
{ :drain_pipe, :is_pending, :consume } = require "ipc"
{ :add_ip, :add_ip4, :add_ip6 }      = require "nft"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_allow, :log_block, :log_info, :log_warn, :now } = require "log"

-- MAC_ZERO : MAC à ignorer (interface sans L2 ou OUTPUT chain en Docker)
MAC_ZERO = "00:00:00:00:00:00"

-- mac_clients[mac_str] = {ipv4, ipv6, last_seen}
-- Permet de résoudre l'adresse cross-family d'un client (ex: IPv4 ↔ IPv6)
mac_clients = {}

-- ip_to_mac[ip_str] = mac_str  (reverse lookup)
ip_to_mac = {}

-- fd de lecture du pipe IPC, injecté par main.moon avant fork()
pipe_rfd = nil

-- Timestamp du dernier refresh de la table voisine (lazy-refresh sur miss)
last_neigh_refresh = 0

-- ── Suivi des clients par adresse MAC ───────────────────────────
-- Mise à jour de mac_clients et ip_to_mac à chaque message IPC reçu.
-- Appelé en callback depuis drain_pipe.
--- Met à jour l'association MAC → {ipv4|ipv6} depuis un message IPC décodé.
-- @tparam table  msg Message IPC décodé ({txid, ip_str, src_port, msg_type, mac_str})
-- @tparam number ts  Timestamp courant (secondes)
-- @treturn nil
update_mac_clients = (msg, ts) ->
  mac = msg.mac_str
  return if mac == MAC_ZERO   -- MAC inconnue (OUTPUT en Docker) : on ignore

  entry = mac_clients[mac] or {}
  entry.last_seen = ts

  if msg.msg_type == 0x41   -- MSG_IPV4
    unless entry.ipv4 == msg.ip_str
      ip_to_mac[entry.ipv4] = nil if entry.ipv4
      entry.ipv4 = msg.ip_str
      ip_to_mac[msg.ip_str] = mac
  else                        -- MSG_IPV6
    unless entry.ipv6 == msg.ip_str
      ip_to_mac[entry.ipv6] = nil if entry.ipv6
      entry.ipv6 = msg.ip_str
      ip_to_mac[msg.ip_str] = mac

  mac_clients[mac] = entry

--- Purge les entrées mac_clients inactives depuis plus de CLIENT_EXPIRY secondes.
-- Appelé périodiquement dans handle_response.
-- @tparam number ts Timestamp courant (secondes)
-- @treturn nil
purge_mac_clients = (ts) ->
  for mac, entry in pairs mac_clients
    if ts - entry.last_seen > CLIENT_EXPIRY
      ip_to_mac[entry.ipv4] = nil if entry.ipv4
      ip_to_mac[entry.ipv6] = nil if entry.ipv6
      mac_clients[mac] = nil
      log_info { action: "client_expired", mac: mac }

--- Résout l'adresse IPv4 d'un client connu par son adresse IPv6 (ou vice-versa)
-- via la table mac_clients.
-- @tparam  string  ip_str Adresse IP du client connue
-- @tparam  string  want   "ipv4" ou "ipv6"
-- @treturn string|nil Adresse IP dans la famille demandée, ou nil si inconnue
resolve_client_family = (ip_str, want) ->
  mac = ip_to_mac[ip_str]
  if mac
    entry = mac_clients[mac]
    result = entry and entry[want]
    return result if result

  -- Miss : lazy-refresh si le cooldown est écoulé
  ts = os.time!
  if ts - last_neigh_refresh > NEIGH_REFRESH_COOLDOWN
    last_neigh_refresh = ts
    neigh.refresh mac_clients, ip_to_mac
    -- Retry après refresh
    mac2 = ip_to_mac[ip_str]
    if mac2
      entry2 = mac_clients[mac2]
      return entry2 and entry2[want]

  nil

--- Process a DNS response packet from NFQUEUE.
-- Drains IPC, validates the transaction, patches TTL+checksums,
-- injects resolved IPs into nftables, and sets the verdict.
-- @tparam cdata  qh_ptr  nfq_q_handle pointer (for nfq_set_verdict)
-- @tparam cdata  nfad    nfq_data pointer
-- @tparam number pkt_id  NFQUEUE packet id
-- @treturn number NF_ACCEPT, NF_DROP, or -1 (verdict already set)
handle_response = (qh_ptr, nfad, pkt_id) ->
  -- ── Drain pipe IPC ───────────────────────────────────────────
  -- Absorbe tous les tokens disponibles de Q0 avant de traiter ce paquet.
  -- Le callback update_mac_clients enrichit la table mac_clients au passage.
  ts = now!
  drain_pipe pipe_rfd, now, (msg) ->
    update_mac_clients msg, ts

  -- ── Payload brut ─────────────────────────────────────────────
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  if payload_len <= 0
    return NF_DROP

  raw = ffi.string payload_ptr[0], payload_len

  -- ── L3 / L4 / L7 ─────────────────────────────────────────────
  -- parse_packet gère IPv4 et IPv6, UDP et TCP, et le header DNS en un seul appel.
  pkt, parse_status = ndpi.parse_packet raw
  unless pkt
    -- Intermediate TCP data segments are DROPped so Q1 can reinject a single
    -- coalesced+TTL-patched packet once the full DNS message is assembled.
    -- TCP control packets (SYN-ACK, pure ACK with no payload, FIN) return nil
    -- without "buffering" and must be passed through unchanged.
    return NF_DROP if parse_status == "buffering"
    return NF_ACCEPT

  -- Pass to nDPI for flow state tracking (TCP sequence, etc.)
  ndpi.get_flow pkt
  if math.random(1000) == 1
    ndpi.purge_flows!
    purge_mac_clients ts

  unless pkt.dns.is_response
    return NF_ACCEPT

  -- La question originale avait src_ip=pkt.ip.dst_ip, src_port=pkt.l4.dst_port
  -- (la réponse est adressée au client LAN).
  client_port = pkt.l4.dst_port
  txid        = pkt.dns.txid

  -- ── Vérification IPC ─────────────────────────────────────────
  -- En mode Docker, on saute la vérification IPC car les requêtes
  -- et réponses sont vues depuis la perspective du conteneur (OUTPUT).
  unless DOCKER_MODE
    unless is_pending txid, pkt.ip.dst_ip, client_port, now
      log_block {
        action:    "response_no_matching_question"
        src_ip:    pkt.ip.src_ip
        dst_ip:    pkt.ip.dst_ip
        txid:      string.format "0x%04x", txid
        rcode:     pkt.dns.rcode
      }
      return NF_DROP
    -- Transaction consommée (one-shot : une réponse par question)
    consume txid, pkt.ip.dst_ip, client_port

  -- ── Parse RR DNS + injection nft ─────────────────────────────
  answers  = ndpi.parse_answers raw, pkt
  -- IP du client LAN (destination de la réponse DNS = source de la question)
  client_ip = pkt.ip.dst_ip
  ip_count = 0
  for ans in *answers
    if ans.rtype == QTYPE.A
      -- Enregistrement A : le client doit avoir une adresse IPv4
      c4 = if pkt.ip.version == 4
        client_ip
      else
        -- DNS transporté en IPv6 : résoudre l'IPv4 via mac_clients
        resolve_client_family client_ip, "ipv4"
      if c4
        add_ip4 c4, ans.rdata_str
        ip_count += 1
      else
        log_warn { action: "no_ipv4_for_client", client: client_ip,
                   record: ans.rdata_str, reason: "mac_not_known" }
    elseif ans.rtype == QTYPE.AAAA
      -- Enregistrement AAAA : le client doit avoir une adresse IPv6
      c6 = if pkt.ip.version == 6
        client_ip
      else
        -- DNS transporté en IPv4 : résoudre l'IPv6 via mac_clients
        resolve_client_family client_ip, "ipv6"
      if c6
        add_ip6 c6, ans.rdata_str
        ip_count += 1
      else
        log_warn { action: "no_ipv6_for_client", client: client_ip,
                   record: ans.rdata_str, reason: "mac_not_known" }

  -- ── Patch TTL + checksums (IPv4 et IPv6) ─────────────────────
  -- patch_and_checksum réécrit les TTL DNS, recalcule le checksum UDP
  -- (pseudo-header IPv4 ou IPv6 selon pkt.ip.version), et le checksum
  -- IP header pour IPv4 (IPv6 n'en a pas).
  patched = ndpi.patch_and_checksum raw, pkt, answers, FORCED_TTL

  -- Log de la réponse
  qnames = table.concat [q.qname for q in *pkt.questions], ","
  log_allow {
    action:      "response_patched"
    src_ip:      pkt.ip.src_ip
    dst_ip:      pkt.ip.dst_ip
    txid:        string.format "0x%04x", txid
    qnames:      qnames
    answers:     ip_count
    ttl_set:     FORCED_TTL
    rcode:       pkt.dns.rcode
    ndpi_master: pkt.ndpi_master
    ndpi_app:    pkt.ndpi_app
  }

  -- ── Verdict avec payload modifié ─────────────────────────────
  -- On appelle nfq_set_verdict directement ici avec le payload modifié,
  -- puis on retourne le sentinel -1 pour que nfq_loop ne repose
  -- un second verdict (ce qui corromprait la queue).
  patched_ptr = ffi.cast "const unsigned char*", patched
  libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr

  -1   -- sentinel : verdict déjà posé, nfq_loop ne doit pas reposer de verdict


-- ── Point d'entrée ───────────────────────────────────────────────
--- Start the Q1 response worker.
-- Blocks in the NFQUEUE loop until the process exits.
-- @tparam number rfd Read end of the IPC pipe from Q0.
run = (rfd) ->
  pipe_rfd = rfd
  -- Pré-remplit mac_clients / ip_to_mac depuis la table ARP/NDP courante,
  -- avant même la première requête DNS. Indispensable pour le cross-family
  -- (IPv6 client → RR A) quand aucun message IPC n'a encore été reçu.
  do
    data = neigh.load!
    mac_clients = data.mac_clients
    ip_to_mac   = data.ip_to_mac
  -- Pré-initialise le module nDPI avant le démarrage de la boucle pour éviter
  -- une latence de 1–2 s sur le premier paquet (ndpi_init_detection_module).
  ndpi.warmup!
  run_queue QUEUE_RESPONSES, handle_response
  ndpi.cleanup!

{ :run }
