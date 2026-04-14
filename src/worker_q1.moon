-- src/worker_q1.moon
-- Worker Q1 : traitement des réponses DNS (UDP/53 dst=LAN, src=resolver).
--
-- Pour chaque paquet :
--   1. Draine le pipe IPC (absorbe les tokens Q0 → table pending)
--   2. Parse L3/L4/L7 via parse/ndpi (IPv4 et IPv6)
--   3. Vérifie que la transaction (txid, dst_ip, dst_port) est dans pending
--   4. Si refusée (entry.refused = true) :
--        a. Remplace le payload DNS par une réponse REFUSED+EDE (Filtered)
--        b. Renvoie le paquet transformé au client
--   5. Si autorisée (entry.refused = false) :
--        a. Parse les RR DNS de la réponse
--        b. Patch TTL de tous les RR → FORCED_TTL secondes
--        c. Ajoute EDE code 0 "Custos vigilat." pour transparence
--        d. Recalcule checksums UDP/TCP et IP
--        e. Ajoute les IPs A/AAAA dans les sets nft (timeout 2m)
--        f. Envoie le paquet modifié avec NF_ACCEPT + payload

{ :ffi, :libnfq } = require "ffi_defs"
{ :QUEUE_RESPONSES, :DOCKER_MODE, :FORCED_TTL, :CLIENT_EXPIRY, :NEIGH_REFRESH_COOLDOWN } = require "config"
neigh = require "neigh"
ndpi = require "parse/ndpi"
{ :QTYPE } = ndpi
{ :get_l2 } = require "parse/ethernet"
{ :drain_pipe, :is_pending, :get_pending_entry, :consume } = require "ipc"
{ :build_refused, :append_ede_to_dns, :EDE_OTHER, :EDE_TTL_TEXT, :EDNS_OPT_EDE } = require "parse/dns"
{ :add_ip4, :add_ip6, :add_mac4, :add_mac6 } = require "nft"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_allow, :log_block, :log_info, :log_warn, :now } = require "log"

-- MAC_ZERO : MAC à ignorer (interface sans L2 ou OUTPUT chain en Docker)
MAC_ZERO = "00:00:00:00:00:00"

-- mac_valid : vrai si mac est une adresse MAC connue et non nulle
mac_valid = (mac) -> mac != "unknown" and mac != MAC_ZERO

-- mac_clients[mac_str] = {ipv4, ipv6, last_seen}
-- Permet de résoudre l'adresse cross-family d'un client (ex: IPv4 ↔ IPv6)
mac_clients = {}

-- ip_to_mac[ip_str] = mac_str  (reverse lookup)
ip_to_mac = {}

-- fd de lecture du pipe IPC, injecté par main.moon avant fork()
pipe_rfd = nil

-- Timestamp du dernier refresh de la table voisine (lazy-refresh sur miss)
last_neigh_refresh = 0

update_mac_clients = nil
drain_ts = 0
drain_on_msg = (msg) ->
  update_mac_clients msg, drain_ts

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

  if msg.ipv4   -- MSG_IPV4 ou MSG_IPV4_REFUSED
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
  l2 = get_l2 nfad

  -- ── Drain pipe IPC ───────────────────────────────────────────
  -- Absorbe tous les tokens disponibles de Q0 avant de traiter ce paquet.
  -- Le callback update_mac_clients enrichit la table mac_clients au passage.
  ts = now!
  drain_ts = ts
  drain_pipe pipe_rfd, now, drain_on_msg

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
  client_ip   = pkt.ip.dst_ip
  client_mac  = ip_to_mac[client_ip] or "unknown"

  -- ── Vérification IPC ─────────────────────────────────────────
  -- En mode Docker, on saute la vérification IPC car les requêtes
  -- et réponses sont vues depuis la perspective du conteneur (OUTPUT).
  entry = nil
  unless DOCKER_MODE
    entry = get_pending_entry txid, pkt.ip.dst_ip, client_port, now
    unless entry
      log_block {
        action:    "response_no_matching_question"
        src_ip:    pkt.ip.src_ip
        dst_ip:    pkt.ip.dst_ip
        vlan:      l2.vlan
        txid:      string.format "0x%04x", txid
        rcode:     pkt.dns.rcode
        client_mac: client_mac
      }
      return NF_DROP
    -- Transaction consommée (one-shot : une réponse par question)
    consume txid, pkt.ip.dst_ip, client_port

  refused = entry and entry.refused or false

  -- ── Branche REFUSED : réponse du serveur transformée en REFUSED+EDE ──
  if refused
    dns_raw    = ndpi.extract_dns_payload raw, pkt
    refused_dns = build_refused { hdr: pkt.dns }, dns_raw
    unless refused_dns
      return NF_DROP
    patched = ndpi.replace_dns_payload raw, pkt, refused_dns
    unless patched
      return NF_DROP
    qnames = table.concat [q.qname for q in *pkt.questions], ","
    log_block {
      action:   "response_refused"
      src_ip:   pkt.ip.src_ip
      dst_ip:   pkt.ip.dst_ip
      vlan:     l2.vlan
      txid:     string.format "0x%04x", txid
      qnames:   qnames
      client_mac: client_mac
    }
    patched_ptr = ffi.cast "const unsigned char*", patched
    libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr
    return -1

  -- ── Branche ACCEPT : patch TTL + EDE + injection nft ─────────
  answers  = ndpi.parse_answers raw, pkt
  -- IP du client LAN (destination de la réponse DNS = source de la question)
  client_ip = pkt.ip.dst_ip
  client_v4 = nil
  client_v6 = nil
  ip_count = 0
  for ans in *answers
    if ans.rtype == QTYPE.A
      -- Enregistrement A : le client doit avoir une adresse IPv4
      client_v4 or= if pkt.ip.version == 4
        client_ip
      else
        -- DNS transporté en IPv6 : résoudre l'IPv4 via mac_clients
        resolve_client_family client_ip, "ipv4"
      if client_v4
        add_ip4 client_v4, ans.rdata_str
        ip_count += 1
      else
        log_warn { action: "no_ipv4_for_client", client: client_ip,
                   record: ans.rdata_str, reason: "mac_not_known" }
      add_mac4 client_mac, ans.rdata_str if mac_valid client_mac
    elseif ans.rtype == QTYPE.AAAA
      -- Enregistrement AAAA : le client doit avoir une adresse IPv6
      client_v6 or= if pkt.ip.version == 6
        client_ip
      else
        -- DNS transporté en IPv4 : résoudre l'IPv6 via mac_clients
        resolve_client_family client_ip, "ipv6"
      if client_v6
        add_ip6 client_v6, ans.rdata_str
        ip_count += 1
      else
        log_warn { action: "no_ipv6_for_client", client: client_ip,
                   record: ans.rdata_str, reason: "mac_not_known" }
      add_mac6 client_mac, ans.rdata_str if mac_valid client_mac

  -- ── Patch TTL + EDE + checksums (IPv4 et IPv6) ───────────────
  -- 1. Extraire le payload DNS brut
  -- 2. Réécrire les TTL DNS
  -- 3. Injecter EDE code 0 "Custos vigilat." pour la transparence envers le client
  -- 4. Reconstruire le paquet IP complet avec le nouveau payload
  dns_raw = ndpi.extract_dns_payload raw, pkt
  new_dns = ndpi.patch_ttl_in_dns dns_raw, answers, FORCED_TTL
  ede_data = string.char(0x00, EDE_OTHER) .. EDE_TTL_TEXT
  new_dns = append_ede_to_dns(new_dns, { { code: EDNS_OPT_EDE, data: ede_data } }) or new_dns
  patched = ndpi.replace_dns_payload raw, pkt, new_dns

  -- Log de la réponse
  qnames = table.concat [q.qname for q in *pkt.questions], ","
  log_allow {
    action:      "response_patched"
    src_ip:      pkt.ip.src_ip
    dst_ip:      pkt.ip.dst_ip
    vlan:        l2.vlan
    txid:        string.format "0x%04x", txid
    qnames:      qnames
    answers:     ip_count
    ttl_set:     FORCED_TTL
    rcode:       pkt.dns.rcode
    ndpi_master: pkt.ndpi_master
    ndpi_app:    pkt.ndpi_app
    client_mac:  client_mac
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
