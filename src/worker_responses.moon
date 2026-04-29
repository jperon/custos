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

{ :ffi, :libc, :libnfq } = require "ffi_defs"
{ :QUEUE_RESPONSES, :FORCED_TTL, :CLIENT_EXPIRY, :NFT_ADD_RETRY_COUNT, :NFT_ADD_BACKOFF_MS, :NFT_ADD_FAILURE_POLICY, :IPC_MATCH_RETRY_ENABLED, :IPC_MATCH_RETRY_COUNT, :IPC_MATCH_RETRY_SLEEP_MS, :AUTH_SESSIONS_FILE } = require "config"
{ :user_for_mac } = require "auth.sessions"
ndpi = require "parse/ndpi"
{ :QTYPE } = ndpi
{ :get_l2 } = require "parse/ethernet"
{ :drain_pipe, :is_pending, :get_pending_entry, :consume } = require "ipc"
{
  :parse, :pack
  :parse_header, :pack_header
  :parse_question, :pack_question, :parse_questions
  :parse_rr, :pack_rr, :parse_rrs
  rcodes: {:REFUSED}
  types: {:A, :AAAA}
  :ede_codes
} = require "ipparse.l7.dns"
{ :add_ip4, :add_ip6, :add_mac4, :add_mac6 } = require "nft"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_info, :log_warn, :log_debug, :now } = require "log"
bit = require "bit"
pack: sp = require"ipparse.lib.pack_compat"
:concat, :insert, :remove = table

-- ── DNS helper functions (ipparse.l7.dns pattern) ───────────────────────

-- EDE codes from RFC 8914 (bidirectional in ipparse)
EDE_BLOCKED = ede_codes.Filtered  -- 17
EDE_TTL_MODIFIED = ede_codes.Forged_Answer       -- 4

-- Message texts
EDE_BLOCKED_TEXT = "Ne intretis."
EDE_TTL_TEXT = "Custos vigilat."

-- Add or replace EDNS EDE option in DNS message
-- Following shelterwall pattern: remove existing OPT RR, add new one with EDE
add_ede = (ede_code, text) =>
  -- Remove existing OPT RR (rtype 0x29)
  for i = #(@additionals or {}), 1, -1
    if @additionals[i].rtype == 0x29
      remove @additionals, i

  -- Add new OPT RR with EDE option (RFC 6891, RFC 8914)
  @additionals or= {}
  insert @additionals, 1, {
    rname: "\0"          -- root name
    rtype: 0x29         -- OPT
    rclass: 0           -- UDP payload size (ignored in response)
    ttl: 0              -- extended RCODE and flags
    rdata: sp ">Hs2", 0x000F, (sp(">H", ede_code)..text)  -- EDE option
  }
  @header.arcount = #(@additionals or {})
  @

-- Build blocked DNS response: REFUSED + synthetic 0.0.0.0/:: + EDE 17
build_blocked_response = (dns_orig, dns_raw) ->
  return nil unless dns_orig and dns_raw

  -- Parse original DNS message (dns_raw is already extracted DNS payload)
  dns = parse dns_raw, 1, false
  return nil unless dns

  -- Set RCODE to REFUSED
  dns.header.rcode = REFUSED

  -- Clear answers, add synthetic 0.0.0.0 or :: based on QTYPE
  dns.answers = {}
  if dns.question and dns.question.qtype
    qtype = dns.question.qtype
    rdata = if qtype == A
      string.char(0, 0, 0, 0)  -- 0.0.0.0
    elseif qtype == AAAA
      string.char(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)  -- ::
    else
      string.char(0, 0, 0, 0)  -- default 0.0.0.0

    -- Add synthetic answer with compression pointer (0xC0 0x0C points to question name)
    dns.answers[1] = {
      rname: string.char(0xC0, 0x0C)  -- pointer to offset 12
      rtype: qtype
      rclass: 1  -- IN
      ttl: 60
      rdata: rdata
    }
    dns.header.ancount = 1

  -- Add EDE 17 (Blocked) with "Ne intretis."
  add_ede dns, EDE_BLOCKED, EDE_BLOCKED_TEXT

  -- Pack DNS message
  tostring dns

-- Add EDE 4 (DNSSEC_Bogus) to DNS message for TTL-modified responses
add_ede_ttl = (dns_payload) ->
  -- Parse DNS message
  dns = parse dns_payload, 1, false
  return dns_payload unless dns

  -- Add EDE 4 with "Custos vigilat."
  add_ede dns, EDE_TTL_MODIFIED, EDE_TTL_TEXT

  -- Pack DNS message
  tostring dns

IPC_RETRY_ENABLED = if IPC_MATCH_RETRY_ENABLED == nil then true else IPC_MATCH_RETRY_ENABLED
IPC_RETRY_COUNT = IPC_MATCH_RETRY_COUNT or 5
IPC_RETRY_SLEEP_MS = IPC_MATCH_RETRY_SLEEP_MS or 20

-- MAC_ZERO : MAC à ignorer (interface sans L2)
MAC_ZERO = "00:00:00:00:00:00"

-- mac_valid : vrai si mac est une adresse MAC connue et non nulle
mac_valid = (mac) -> mac != "unknown" and mac != MAC_ZERO

{ :try_add_with_retries } = require "nft_add_helper"

-- mac_clients[mac_str] = {ipv4, ipv6, last_seen}
-- Permet de résoudre l'adresse cross-family d'un client (ex: IPv4 ↔ IPv6)
mac_clients = {}

-- ip_to_mac[ip_str] = mac_str  (reverse lookup)
ip_to_mac = {}

-- fd de lecture du pipe IPC, injecté par main.moon avant fork()
pipe_rfd = nil

sleep_req = ffi.new "timespec_t[1]"

update_mac_clients = nil
drain_ts = 0
drain_on_msg = (msg) ->
  update_mac_clients msg, drain_ts

sleep_ms = (ms) ->
  return unless ms and ms > 0
  sleep_req[0].tv_sec = math.floor ms / 1000
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  libc.nanosleep sleep_req, nil

retry_pending_match = (txid, client_ip, client_port, resolver_ip) ->
  return nil, 0, 0 unless IPC_RETRY_ENABLED
  tries = IPC_RETRY_COUNT or 0
  wait_ms = IPC_RETRY_SLEEP_MS or 0
  return nil, 0, 0 if tries <= 0

  total_wait_ms = 0
  for i = 1, tries
    sleep_ms wait_ms
    total_wait_ms += wait_ms
    ts = now!
    drain_ts = ts
    drain_pipe pipe_rfd, now, drain_on_msg
    entry = get_pending_entry txid, client_ip, client_port, resolver_ip, now
    return entry, i, total_wait_ms if entry

  nil, tries, total_wait_ms

-- ── Suivi des clients par adresse MAC ───────────────────────────
-- Mise à jour de mac_clients et ip_to_mac à chaque message IPC reçu.
-- Appelé en callback depuis drain_pipe.
--- Met à jour l'association MAC → {ipv4|ipv6} depuis un message IPC décodé.
-- @tparam table  msg Message IPC décodé ({txid, ip_str, src_port, msg_type, mac_str})
-- @tparam number ts  Timestamp courant (secondes)
-- @treturn nil
update_mac_clients = (msg, ts) ->
  mac = msg.mac_str
  return if mac == MAC_ZERO   -- MAC inconnue : on ignore

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
      entry.ips = nil
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
  drain_ts = ts
  drain_pipe pipe_rfd, now, drain_on_msg

  -- ── Payload brut ─────────────────────────────────────────────
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  if payload_len <= 0
    return NF_DROP

  raw = ffi.string payload_ptr[0], payload_len

  -- ── L2 ────────────────────────────────────────────────────
  -- MAC source via nfq_get_packet_hw() ; MAC destination non exposée par libnfq.
  l2 = get_l2 nfad

  -- ── L3 / L4 / L7 ───────────────────────────────────────────────
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
    ndpi.purge_tcp_buffers!
    purge_mac_clients ts

  unless pkt.dns.is_response
    return NF_ACCEPT

  -- La question originale avait src_ip=pkt.ip.dst_ip, src_port=pkt.l4.dst_port
  -- (la réponse est adressée au client LAN).
  client_port = pkt.l4.dst_port
  txid        = pkt.dns.txid
  client_ip   = pkt.ip.dst_ip
  resolver_ip = pkt.ip.src_ip
  -- MAC du client : resolution depuis la table ip_to_mac alimentée par Q0 via IPC.
  -- mac_dst n'est jamais exposée par libnfq ; on utilise le reverse-lookup local.
  client_mac = ip_to_mac[client_ip] or "unknown"
  -- Utilisateur authentifié (nil si l'IP n'a pas de session valide)
  -- L'indexation par MAC permet de reconnaître un client authentifié
  -- en IPv6 quand ses paquets IPv4 arrivent (et vice-versa) de manière O(1).
  user        = user_for_mac client_mac, client_ip, AUTH_SESSIONS_FILE

  -- ── Vérification IPC ─────────────────────────────────────────
  entry = get_pending_entry txid, pkt.ip.dst_ip, client_port, resolver_ip, now
  unless entry
    retry_attempts = 0
    retry_wait_ms = 0
    entry, retry_attempts, retry_wait_ms = retry_pending_match txid, pkt.ip.dst_ip, client_port, resolver_ip
    if entry
      log_info {
        action: "response_matched_after_retry"
        src_ip: pkt.ip.src_ip
        dst_ip: pkt.ip.dst_ip
        txid: string.format "0x%04x", txid
        retry_attempts: retry_attempts
        retry_wait_ms: retry_wait_ms
        user: user
      }
    else
      log_debug {
        action:    if retry_attempts > 0 then "response_no_matching_question_after_retry" else "response_no_matching_question"
        src_ip:    pkt.ip.src_ip
        dst_ip:    pkt.ip.dst_ip
        vlan:      l2.vlan
        txid:      string.format "0x%04x", txid
        rcode:     pkt.dns.rcode
        client_mac: client_mac
        retry_attempts: retry_attempts
        retry_wait_ms: retry_wait_ms
        user: user
      }
      return NF_DROP
  -- Transaction consommée (one-shot : une réponse par question)
  consume txid, pkt.ip.dst_ip, client_port, resolver_ip

  refused = entry and entry.refused or false
  dnsonly = entry and entry.dnsonly or false

  -- ── Branche REFUSED : réponse du serveur transformée en REFUSED+EDE ──
  if refused
    dns_raw    = ndpi.extract_dns_payload raw, pkt
    refused_dns = build_blocked_response pkt.dns, dns_raw
    unless refused_dns
      return NF_DROP
    patched = ndpi.replace_dns_payload raw, pkt, refused_dns
    unless patched
      return NF_DROP
    qnames = table.concat [q.qname for q in *pkt.questions], ","
    log_debug {
      action:   "response_refused"
      src_ip:   pkt.ip.src_ip
      dst_ip:   pkt.ip.dst_ip
      vlan:     l2.vlan
      txid:     string.format "0x%04x", txid
      qnames:   qnames
      client_mac: client_mac
      user:     user
    }
    patched_ptr = ffi.cast "const unsigned char*", patched
    libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr
    return -1

  -- ── Branche ACCEPT : patch TTL + EDE + injection nft ─────────
  -- En mode "dnsonly", on ne modifie pas les sets nft : les IPs résolues ne
  -- sont pas autorisées dans les sets — la redirection HTTP/80 reste active.
  answers  = ndpi.parse_answers raw, pkt
  -- IP du client LAN (destination de la réponse DNS = source de la question)
  client_ip = pkt.ip.dst_ip
  client_v4 = nil
  client_v6 = nil
  ip_count = 0
  records_to_add = 0
  success_any = false
  no_ipv4_records = {}
  no_ipv6_records = {}
  for ans in *answers
    if ans.rtype == QTYPE.A
      -- Enregistrement A : le client doit avoir une adresse IPv4
      client_v4 or= if pkt.ip.version == 4
        client_ip
      else
        -- DNS transporté en IPv6 : résoudre l'IPv4 via mac_clients
        resolve_client_family client_ip, "ipv4"
      unless dnsonly
        if client_v4
          records_to_add += 1
          ok = try_add_with_retries add_ip4, client_v4, ans.rdata_str
          ip_count += 1 if ok
          success_any or= ok
        else
          no_ipv4_records[#no_ipv4_records + 1] = ans.rdata_str
        if mac_valid client_mac
          m_ok = try_add_with_retries add_mac4, client_mac, ans.rdata_str
          success_any or= m_ok
    elseif ans.rtype == QTYPE.AAAA
      -- Enregistrement AAAA : le client doit avoir une adresse IPv6
      client_v6 or= if pkt.ip.version == 6
        client_ip
      else
        -- DNS transporté en IPv4 : résoudre l'IPv6 via mac_clients
        resolve_client_family client_ip, "ipv6"
      unless dnsonly
        if client_v6
          records_to_add += 1
          ok = try_add_with_retries add_ip6, client_v6, ans.rdata_str
          ip_count += 1 if ok
          success_any or= ok
        else
          no_ipv6_records[#no_ipv6_records + 1] = ans.rdata_str
        if mac_valid client_mac
          m_ok = try_add_with_retries add_mac6, client_mac, ans.rdata_str
          success_any or= m_ok

  -- Logguer les cas cross-family sans IP connue (groupés par réponse)
  if #no_ipv4_records > 0
    log = if mac_valid(client_mac) then log_info else log_warn
    log { action: "no_ipv4_for_client", client: client_ip, count: #no_ipv4_records,
          records: table.concat(no_ipv4_records, " "),
          reason: "client_ipv4_unknown", mac_fallback: mac_valid(client_mac), user: user }
  if #no_ipv6_records > 0
    log = if mac_valid(client_mac) then log_info else log_warn
    log { action: "no_ipv6_for_client", client: client_ip, count: #no_ipv6_records,
          records: table.concat(no_ipv6_records, " "),
          reason: "client_ipv6_unknown", mac_fallback: mac_valid(client_mac), user: user }

  -- ── Patch TTL + EDE + checksums (IPv4 et IPv6) ───────────────
  -- 1. Extraire le payload DNS brut
  -- 2. Réécrire les TTL DNS
  -- 3. Injecter EDE code 0 "Custos vigilat." pour la transparence envers le client
  -- 4. Reconstruire le paquet IP complet avec le nouveau payload
  dns_raw = ndpi.extract_dns_payload raw, pkt
  new_dns = ndpi.patch_ttl_in_dns dns_raw, answers, FORCED_TTL
  new_dns = add_ede_ttl(new_dns) or new_dns
  patched = ndpi.replace_dns_payload raw, pkt, new_dns

  -- Log de la réponse
  qnames = table.concat [q.qname for q in *pkt.questions], ","
  log_debug {
    action:      if dnsonly then "response_dnsonly" else "response_patched"
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
    user:        user
  }

  -- If we had records to add but none succeeded, respect policy
  if records_to_add > 0 and not success_any
    if NFT_ADD_FAILURE_POLICY == "fail-closed"
      log_debug { action: "nft_add_failed_policy_fail_closed", txid: string.format("0x%04x", txid), client_ip: client_ip, qnames: qnames, user: user }
      return NF_DROP
    else
      log_warn { action: "nft_add_failed_fail_open", txid: string.format("0x%04x", txid), client_ip: client_ip, qnames: qnames, user: user }

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
run = (queue_num, rfd) ->
  pipe_rfd = rfd
  -- Pré-remplit mac_clients / ip_to_mac depuis la table ARP/NDP courante,
  -- avant même la première requête DNS. Indispensable pour le cross-family
  -- (IPv6 client → RR A) quand aucun message IPC n'a encore été reçu.
  -- mac_clients et ip_to_mac démarrent vides ; ils sont alimentés organiquement
  -- par les messages IPC reçus de Q0 (update_mac_clients dans drain_on_msg).
  -- Pré-initialise le module nDPI avant le démarrage de la boucle pour éviter
  -- une latence de 1–2 s sur le premier paquet (ndpi_init_detection_module).
  ndpi.warmup!
  run_queue tonumber(queue_num), handle_response
  ndpi.cleanup!

{ :run }
