-- src/worker_responses.moon
-- Worker response : traitement des réponses DNS (UDP/53 dst=LAN, src=resolver).
--
-- Pour chaque paquet :
--   1. Draine le pipe IPC (absorbe les tokens question → table pending)
--   2. Parse L3/L4/L7 via parse/packet (IPv4 et IPv6)
--   3. Vérifie que la transaction (txid, dst_ip, dst_port) est dans pending
--   4. Si refusée (entry.refused = true) :
--        a. Remplace le payload DNS par une réponse REFUSED+EDE (Filtered)
--        b. Renvoie le paquet transformé au client
--   5. Si autorisée (entry.refused = false) :
--        a. Parse les RR DNS de la réponse
--        b. Conserve le payload tel quel sauf modification explicite (ex: strip HTTPS/SVCB)
--        c. Ajoute EDE uniquement si la réponse est effectivement modifiée
--        d. Recalcule checksums UDP/TCP et IP
--        e. Ajoute les IPs A/AAAA dans les sets nft (timeout = TTL RR + grace, borné)
--        f. Envoie le paquet modifié avec NF_ACCEPT + payload

{ :ffi, :libc, :libnfq } = require "ffi_defs"
config = require "config"
runtime_cfg = config.runtime or {}
ipc_cfg = config.ipc or {}
match_retry_cfg = ipc_cfg.match_retry or {}
dns_cfg = config.dns or {}
ttl_cfg = dns_cfg.ttl_grace or {}
auth_cfg = config.auth or {}
clients_cfg = config.clients or {}
{ :user_for_mac } = require "auth.sessions"
{ :parse_ip4, :parse_ip6, :parse_udp, :parse_tcp, :parse_dns, :ip2s, dns_types: QTYPE } = require "lib.packet_parsing"
{ :skip_ipv6_ext_hdrs, :new_dns_tcp_stream } = require "packet_utils"
{ :get_l2 } = require "nfq/ethernet"
{ :drain_pipe, :is_pending, :get_pending_entry, :consume } = require "ipc"
{ :add_ip4, :add_ip6, :add_mac4, :add_mac6, :get_last_seq, :wait_ack, :drain_ack } = require "nft_queue"
{ :run_queue, :NF_ACCEPT, :NF_DROP } = require "nfq_loop"
{ :log_info, :log_warn, :log_debug, :log_allow, :log_block, :now, :set_action_prefix } = require "log"
{ :build_blocked_response, :build_nxdomain_response, :build_sinkhole_response, :build_cname_response, :strip_https_rr, :add_ede_modified, :clear_ad_bit, :patch_modified_dns } = require "dns_ede"

-- Motif EDE pour un blocage décidé par le validateur amont (et non par une règle
-- locale) : ne pas réutiliser `entry.reason` (la raison d'AUTORISATION locale,
-- ex. « Allowed by rule: Utilisateurs »), qui serait trompeuse dans l'EDE.
VALIDATOR_REASON = "Filtered by upstream validator"
{ :rr_timeout, :detect_wildcards, :inject } = require "response_inject"
dns_classify = require "dns_classify"
second_opinion = require "second_opinion"
dup_query = require "dup_query"
raw_send = require "raw_send"
so_cfg = config.second_opinion or {}
bit = require "bit"

-- ── Retry upstream (SERVFAIL/REFUSED) ──────────────────────────────
-- cf. config.dns.upstream_retry. Ré-interroge le MÊME résolveur après une
-- réponse transitoirement en échec, plutôt que de la transmettre au client.
retry_cfg     = (config.dns or {}).upstream_retry or {}
retry_enabled = retry_cfg.enabled and true or false
retry_max     = tonumber(retry_cfg.max_attempts) or 2
retry_rcodes  = {}
for rc in *(retry_cfg.rcodes or { 2, 3, 5 })
  retry_rcodes[rc] = true
pending_ttl   = ((config.ipc or {}).pending_ttl) or 5
-- Sockets RAW (HDRINCL) par famille pour réémettre les requêtes ; init dans run().
retry_fds     = {}
RCODE_NXDOMAIN = 3
-- Cache des noms durablement NXDOMAIN (retry inutile) : un nom n'y entre que si
-- même le retry reste NXDOMAIN, et en sort dès qu'il résout de nouveau (NOERROR).
ttl_set       = require "lib.ttl_set"
nxdomain_bad  = ttl_set.new (retry_cfg.nxdomain_bad_max or 4096), (retry_cfg.nxdomain_bad_ttl or 60), now

-- État « second avis » (nil si désactivé), initialisé dans run().
so_state = nil

-- Helper : pose un verdict NFQUEUE avec payload optionnel.
set_verdict = (qh_ptr, pkt_id, verdict, payload=nil) ->
  if payload
    ptr = ffi.cast "const unsigned char*", payload
    libnfq.nfq_set_verdict qh_ptr, pkt_id, verdict, #payload, ptr
  else
    libnfq.nfq_set_verdict qh_ptr, pkt_id, verdict, 0, nil

-- ── Constantes L3/L4 et helpers checksums ──────────────────────
-- Byte-level (big-endian) + recalcul checksums IPv4/UDP/TCP factorisés dans
-- lib.checksums (mutation FFI en place, partagée avec les futurs workers).

{ :PROTO_UDP, :PROTO_TCP } = require "lib.checksums"

tcp_state = new_dns_tcp_stream!

-- Reconstruction de paquet et formatage des RR DNS factorisés (fonctions pures).
{ :replace_dns_payload, :parse_answers, :build_query_from_response } = require "lib.dns_response"

-- ── Parsing L3/L4/L7 ────────────────────────────────────────────

-- Extrait ip, l4, dns_msg, dns_raw, ip_ihl depuis un paquet IP brut.
-- Retourne nil, "status" sur les cas spéciaux.
-- ip_ihl est l'offset 0-based (octets) de L4 depuis le début du paquet.
parse_packet = (raw) ->
  ver = bit.rshift raw\byte(1), 4
  ip = if ver == 4
    ip4, _ = parse_ip4 raw
    ip4
  elseif ver == 6
    ip6, _ = parse_ip6 raw
    ip6
  return nil, "parse_failed" unless ip

  l4_off = ip.data_off
  proto  = ip.protocol or ip.next_header
  ip_ihl = ip.payload_off or (ip.data_off - 1)   -- offset 0-based de L4

  if ip.version == 6
    p = ffi.cast "const uint8_t*", raw
    proto, l4_off_0based = skip_ipv6_ext_hdrs p, #raw, ip.next_header
    return nil, "parse_failed" unless proto
    l4_off = l4_off_0based + 1
    ip_ihl = l4_off_0based

  if proto == PROTO_UDP
    udp, _ = parse_udp raw, l4_off
    return nil, "parse_failed" unless udp
    dns_raw = raw\sub udp.data_off, udp.off + udp.len - 1
    dns_msg, _ = parse_dns dns_raw, 1, false
    return nil, "parse_failed" unless dns_msg
    udp.proto = "udp"
    return ip, udp, dns_msg, dns_raw, ip_ihl

  elseif proto == PROTO_TCP
    tcp, _ = parse_tcp raw, l4_off
    return nil, "parse_failed" unless tcp
    payload = raw\sub tcp.data_off
    is_fin_rst = bit.band(tcp.flags, 0x05) != 0
    has_payload = payload != ""
    -- Clé de reassembly : octets IP bruts (largeur fixe, byte-safe) plutôt que
    -- ip2s (évite deux inet_ntop + allocations par segment TCP). Clé opaque,
    -- jamais re-parsée.
    key = "#{ip.src}|#{tcp.spt}|#{ip.dst}|#{tcp.dpt}"
    buf, init_seq, first_seg = tcp_state.feed key, payload, tcp.flags, tcp.seq_n
    unless buf
      return nil, if is_fin_rst or not has_payload then "tcp_control" else "buffering"
    dns_raw = buf\sub 3
    dns_msg, _ = parse_dns dns_raw, 1, false
    return nil, "parse_failed" unless dns_msg
    tcp.proto = "tcp"
    tcp.tcp_init_seq = init_seq
    tcp.tcp_single_segment = first_seg
    tcp.tcp_dns_raw = dns_raw
    return ip, tcp, dns_msg, dns_raw, ip_ihl

  nil, "parse_failed"

-- ── Chargement paresseux de filter pour éviter de tirer ip_whitelist (libnftnl)
-- au chargement du module — critique pour les tests unitaires.
_filter = nil
run_on_response = (rule_id, dns_raw, reason, ctx_extra=nil) ->
  _filter or= require "filter"
  _filter.run_on_response rule_id, dns_raw, reason, ctx_extra

-- Load filter rules to identify auth-only wildcard rules
-- rules_metadata is passed from main.moon to avoid recompiling (which would reload domain lists)
rules_metadata = nil

-- Cache of auth-only wildcard rules (requires_auth=true, #dns_refs==0)
-- Détection factorisée dans response_inject.detect_wildcards (partagé avec DoH).
auth_wildcard_rules = {}
load_auth_wildcard_rules = (metadata) ->
  rules_metadata = metadata
  auth_wildcard_rules = detect_wildcards metadata
  log_info -> { action: "auth_wildcard_rules_loaded", count: #auth_wildcard_rules, rules: table.concat(auth_wildcard_rules, ", ") }

IPC_RETRY_ENABLED = if match_retry_cfg.enabled == nil then true else match_retry_cfg.enabled
IPC_RETRY_COUNT = match_retry_cfg.count or 5
IPC_RETRY_SLEEP_MS = match_retry_cfg.sleep_ms or 20

-- MAC_ZERO : MAC à ignorer (interface sans L2)
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

sleep_req = ffi.new "timespec_t[1]"
CLOCK_MONOTONIC = 1

-- Compteur de purge périodique (hot-path, sans math.random) : déclenche
-- tcp_state.purge et purge_mac_clients tous les 1000 paquets.
purge_counter = 0

-- Benchmark : buffer timespec réutilisé
_benchmark_ts = ffi.new "timespec_t[1]"

--- Retourne les millisecondes depuis boot (CLOCK_MONOTONIC).
-- @treturn number
current_benchmark_ms = ->
  libc.clock_gettime CLOCK_MONOTONIC, _benchmark_ts
  tonumber(_benchmark_ts[0].tv_sec) * 1000 + math.floor(tonumber(_benchmark_ts[0].tv_nsec) / 1000000)

--- Différence positive entre deux jalons benchmark en millisecondes.
-- @tparam number|nil finish Jalons de fin
-- @tparam number|nil start  Jalons de début
-- @treturn number|nil Durée, ou nil si invalide
bench_delta = (finish, start) ->
  return nil unless finish and start
  delta = finish - start
  if delta >= 0 then delta else nil

--- Construit les champs de la ligne benchmark ALLOW/BLOCK (fonction pure).
-- Réunit le verdict (depuis `entry`), les métadonnées de la requête (`info`,
-- extraites de la réponse DNS) et les jalons de latence (`deltas`).
-- @tparam table entry  Transaction IPC (refused, reason, rule_id, dnsonly)
-- @tparam table info   Métadonnées : client_mac, vlan, client_ip, resolver_ip,
--                      client_port, txid, af, user, qname, qtype, retry_*
-- @tparam table deltas Jalons : delta_ms (→ q_to_response_ms), question_proc_ms,
--                      response_entry_ms, drain_ms, payload_ms, parse_ms, match_ms, log_ms
-- @treturn table  Champs prêts pour log_allow/log_block
-- @treturn string Verdict : "block" si entry.refused, sinon "allow"
build_benchmark_fields = (entry, info, deltas) ->
  fields = {
    action:   "dns_benchmark"
    worker:   "dns"
    mac_src:  info.client_mac
    vlan:     info.vlan
    src_ip:   info.client_ip
    dst_ip:   info.resolver_ip
    dst_port: info.client_port
    txid:     string.format "0x%04x", info.txid
    af:       info.af
    user:     info.user
    qname:    info.qname
    qtype:    info.qtype
    reason:   entry.reason
    rule:     entry.rule_id
    dnsonly:  entry.dnsonly
    q_to_response_ms: deltas.delta_ms
    question_proc_ms:  deltas.question_proc_ms
    response_entry_ms: deltas.response_entry_ms
    drain_ms:   deltas.drain_ms
    payload_ms: deltas.payload_ms
    parse_ms:   deltas.parse_ms
    match_ms:   deltas.match_ms
    log_ms:     deltas.log_ms
    retry_wait_ms:  info.retry_wait_ms
    retry_attempts: info.retry_attempts
  }
  fields, (entry.refused and "block" or "allow")

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
    if ts - entry.last_seen > (clients_cfg.expiry or 300)
      ip_to_mac[entry.ipv4] = nil if entry.ipv4
      ip_to_mac[entry.ipv6] = nil if entry.ipv6
      entry.ips = nil
      mac_clients[mac] = nil
      log_info -> { action: "client_expired", mac: mac }

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

-- rr_timeout et patch_modified_dns sont désormais fournis par les modules
-- partagés response_inject / dns_ede (réexportés en fin de fichier pour les
-- tests existants).

--- Finalise une réponse d'origine A (pose le verdict NFQUEUE lui-même).
-- Utilisée en ligne (verdict validateur déjà connu) et au déparquage (réponse
-- validateur B arrivée, ou budget dépassé → override=nil = fail-open).
-- @tparam table ctx       Contexte paquet capturé (qh_ptr, pkt_id, raw, ip, …).
-- @tparam table|nil override Verdict validateur : nil (pass), {kind:"block"} ou
--                            {kind:"redirect", cname_target, a, aaaa, ttl}.
-- @treturn nil (le verdict est posé via nfq_set_verdict)
finalize_a = (ctx, override) ->
  { :qh_ptr, :pkt_id, :raw, :ip, :l4, :ip_ihl, :dns_msg, :dns_raw, :entry } = ctx
  resolver_ip, dnsonly = ctx.resolver_ip, ctx.dnsonly
  nft_rule_id, ack_corr = ctx.nft_rule_id, ctx.ack_corr
  client_ip, client_mac, user = ctx.client_ip, ctx.client_mac, ctx.user
  txid, vlan = ctx.txid, ctx.vlan
  src_ip, dst_ip = ctx.src_ip, ctx.dst_ip
  reason = entry and entry.reason or ""
  txid_hex = string.format "0x%04x", txid

  -- Résolveur d'adresse client par famille (mémoïsé), partagé override/normal.
  client_v4, client_v6 = nil, nil
  client_addr = (fam) ->
    if fam == "ipv4"
      client_v4 or= (ip.version == 4 and client_ip or resolve_client_family client_ip, "ipv4")
      client_v4
    else
      client_v6 or= (ip.version == 6 and client_ip or resolve_client_family client_ip, "ipv6")
      client_v6

  -- Options inject partagées (réutilisées avec inject_nft ajusté plus bas).
  inject_opts = {
    :client_addr, :client_mac, :user
    rule_id:      nft_rule_id
    wildcard_ids: auth_wildcard_rules
    :ack_corr
    inject_nft:   true
    :mac_valid
    add_ip:  { ipv4: add_ip4, ipv6: add_ip6 }
    add_mac: { ipv4: add_mac4, ipv6: add_mac6 }
  }

  inject_answers = (answers) ->
    drain_ack!
    inject answers, inject_opts

  -- Helper override : strip HTTPS/SVCB, repatche le paquet et pose le verdict
  -- (NF_DROP si la construction ou le patch échoue).
  patch_and_accept = (new_dns, action_label) ->
    if new_dns
      new_dns = strip_https_rr(new_dns) or new_dns
      patched = replace_dns_payload raw, ip, l4, ip_ihl, new_dns
      if patched
        log_debug -> { action: action_label, src_ip: src_ip, dst_ip: dst_ip, txid: txid_hex, client_mac: client_mac, user: user }
        return set_verdict qh_ptr, pkt_id, NF_ACCEPT, patched
    set_verdict qh_ptr, pkt_id, NF_DROP

  -- ── Override : blocage NXDOMAIN + EDE (Filtered) ──────────────
  if override and override.kind == "block"
    return patch_and_accept build_nxdomain_response(dns_msg, dns_raw, VALIDATOR_REASON), "response_validator_block"

  -- ── Override : sinkhole (reproduction 0.0.0.0/:: + EDE Filtered) ─
  if override and override.kind == "sinkhole"
    sink = { a: override.a or {}, aaaa: override.aaaa or {}, ttl: override.ttl }
    return patch_and_accept build_sinkhole_response(dns_msg, dns_raw, VALIDATOR_REASON, sink), "response_validator_sinkhole"

  -- ── Override : réorientation (CNAME) ──────────────────────────
  if override and override.kind == "redirect" and override.cname_target
    -- Sauf si la réponse d'origine porte déjà le même CNAME cible (passthrough).
    unless dns_classify.has_cname_target dns_msg, dns_raw, override.cname_target
      target_rrs = { a: override.a or {}, aaaa: override.aaaa or {}, ttl: override.ttl }
      new_dns = build_cname_response dns_msg, dns_raw, override.cname_target, VALIDATOR_REASON, target_rrs
      if new_dns
        new_dns = clear_ad_bit new_dns
        patched = replace_dns_payload raw, ip, l4, ip_ihl, new_dns
        if patched
          -- Injecte les IP de réorientation pour que le client puisse les atteindre.
          redirect_answers = {}
          for r in *(override.a or {})
            redirect_answers[#redirect_answers + 1] = { family: "ipv4", addr: ip2s(r), ttl: override.ttl }
          for r in *(override.aaaa or {})
            redirect_answers[#redirect_answers + 1] = { family: "ipv6", addr: ip2s(r), ttl: override.ttl }
          if #redirect_answers > 0
            inject_answers redirect_answers
            pending_seq = get_last_seq!
            wait_ack pending_seq, ack_corr, (-> drain_pipe pipe_rfd, now, drain_on_msg) if pending_seq
          log_debug -> { action: "response_validator_redirect", target: override.cname_target, src_ip: src_ip, dst_ip: dst_ip, txid: txid_hex, client_mac: client_mac, user: user }
          return set_verdict qh_ptr, pkt_id, NF_ACCEPT, patched
      return set_verdict qh_ptr, pkt_id, NF_DROP
    -- même CNAME → on continue vers le chemin normal (passthrough)

  -- ── Chemin normal (pass) : callbacks on_response + injection nft ──
  response_hooks = (entry and entry.response_rule_ids and #entry.response_rule_ids > 0) and entry.response_rule_ids or nft_rule_id
  resp_ctx = run_on_response response_hooks, dns_raw, reason, { resolver_ip: resolver_ip }

  dns_raw = resp_ctx.dns_raw
  payload_modified = resp_ctx.modified
  inject_nft = resp_ctx.inject_nft

  answers_dns = dns_msg
  parsed_modified, _ = parse_dns dns_raw, 1, false
  answers_dns = parsed_modified if parsed_modified

  answers = {}
  for a in *parse_answers answers_dns
    if a.rtype == QTYPE.A or a.rtype == QTYPE.AAAA
      fam = a.rtype == QTYPE.AAAA and "ipv6" or "ipv4"
      answers[#answers + 1] = { family: fam, addr: a.rdata_str, ttl: a.ttl }

  drain_ack! if inject_nft and not dnsonly

  inject_opts.inject_nft = inject_nft
  inj = inject answers, inject_opts
  ip_count       = inj.ip_count
  records_to_add = inj.records_to_add
  success_any    = inj.success_any

  for fam, recs in pairs { ipv4: inj.no_v4, ipv6: inj.no_v6 }
    if #recs > 0
      log_fn = if mac_valid(client_mac) then log_info else log_warn
      log_fn -> { action: "no_#{fam}_for_client", client: client_ip, count: #recs, records: table.concat(recs, " "), reason: "client_#{fam}_unknown", mac_fallback: mac_valid(client_mac), user: user }

  new_dns, dns_modified = patch_modified_dns dns_raw, reason
  payload_modified = payload_modified or dns_modified
  patched = nil
  if payload_modified
    patched = replace_dns_payload raw, ip, l4, ip_ihl, new_dns
    return set_verdict qh_ptr, pkt_id, NF_DROP unless patched

  qnames = table.concat [q.name for q in *dns_msg.questions], ","
  log_debug -> {
    action:      resp_ctx.action_label or (payload_modified and "response_patched" or "response_allow")
    src_ip: src_ip, dst_ip: dst_ip, vlan: vlan
    txid: txid_hex
    qnames: qnames, answers: ip_count, nft_rule_id: nft_rule_id
    payload_modified: payload_modified, rcode: dns_msg.header.rcode
    client_mac: client_mac, user: user
  }

  if records_to_add > 0 and not success_any
    if ((config.nft or {}).add_failure_policy or "fail-closed") == "fail-closed"
      log_debug -> { action: "nft_add_failed_policy_fail_closed", txid: txid_hex, client_ip: client_ip, qnames: qnames, user: user }
      return set_verdict qh_ptr, pkt_id, NF_DROP
    else
      log_warn -> { action: "nft_add_failed_fail_open", txid: txid_hex, client_ip: client_ip, qnames: qnames, user: user }

  if not dnsonly and records_to_add > 0
    pending_seq = get_last_seq!
    wait_ack pending_seq, ack_corr, (-> drain_pipe pipe_rfd, now, drain_on_msg) if pending_seq

  if payload_modified
    set_verdict qh_ptr, pkt_id, NF_ACCEPT, patched
  else
    set_verdict qh_ptr, pkt_id, NF_ACCEPT

--- Balaye les réponses A parquées dont le budget est dépassé (fail-open).
sweep_parked = ->
  return unless so_state and so_state.has_parked!
  for ctx in *so_state.expired current_benchmark_ms!
    finalize_a ctx, nil

--- Tente un retry upstream après une réponse transitoirement en échec.
-- Réémet la requête vers LE MÊME résolveur (src client spoofée) via un socket
-- RAW, garde la transaction `entry` vivante (non consommée, expiry prolongé) et
-- incrémente son compteur d'essais. Best-effort, ne bloque jamais.
-- @tparam table  entry      Transaction en attente (mutée : upstream_retries, expire).
-- @tparam table  dns_msg    Réponse DNS parsée.
-- @tparam string dns_raw    Payload DNS brut de la réponse.
-- @tparam table  ip         En-tête IP parsé de la réponse.
-- @tparam table  l4         En-tête L4 parsé de la réponse.
-- @tparam string resolver_ip IP du résolveur (= src de la réponse).
-- @treturn boolean true si une requête de retry a été émise (→ NF_DROP attendu).
-- Tient aussi à jour `nxdomain_bad` : un nom résolu (NOERROR) en sort ; un nom
-- dont même le retry reste NXDOMAIN (budget épuisé) y entre pour ne plus être
-- retenté pendant `nxdomain_bad_ttl`.
try_upstream_retry = (entry, dns_msg, dns_raw, ip, l4, resolver_ip) ->
  return false unless retry_enabled
  return false if entry.refused
  return false unless l4.proto == "udp"
  rc = bit.band dns_msg.header.ra_z_rcode, 0x0f
  q1 = dns_msg.questions and dns_msg.questions[1]
  qname = q1 and q1.name and q1.name\lower!
  -- Réponse positive : le nom est (de nouveau) vivant → ne plus le supprimer.
  if rc == 0
    nxdomain_bad.remove qname
    return false
  return false unless retry_rcodes[rc]
  -- NXDOMAIN d'un nom déjà connu durablement absent : servir vite, sans retry.
  return false if rc == RCODE_NXDOMAIN and nxdomain_bad.has qname
  unless (entry.upstream_retries or 0) < retry_max
    -- Budget épuisé : si NXDOMAIN persiste, mémoriser le nom comme « mauvais ».
    nxdomain_bad.add qname if rc == RCODE_NXDOMAIN
    return false
  fd = retry_fds[ip.version == 6 and "ipv6" or "ipv4"]
  return false unless fd
  qdcount = dns_msg.header.qdcount or (dns_msg.questions and #dns_msg.questions) or 1
  query_raw = build_query_from_response dns_raw, qdcount
  return false unless query_raw
  pkt = dup_query.build_query ip, l4, query_raw
  return false unless pkt
  entry.upstream_retries = (entry.upstream_retries or 0) + 1
  entry.expire = now! + pending_ttl   -- garder la transaction vivante jusqu'au retour
  raw_send.send fd, ip.version, pkt, resolver_ip
  true

--- Ouvre les sockets RAW (HDRINCL) du retry upstream (un par famille).
-- Idempotent, best-effort. Appelé par run() ; exposé pour les tests.
-- @treturn nil
arm_retry_fds = ->
  return unless retry_enabled
  for fam, ver in pairs { ipv4: 4, ipv6: 6 }
    continue if retry_fds[fam]
    fd = raw_send.open ver
    retry_fds[fam] = fd if fd

--- Traduit un résultat dns_classify en override pour finalize_a.
-- Toujours non-nil ({kind:"pass"} pour une réponse normale) afin de distinguer
-- « verdict connu = pass » de « verdict pas encore reçu » dans le cache.
-- @tparam table vi Résultat de dns_classify.classify.
-- @treturn table { kind = "block"|"sinkhole"|"redirect"|"pass", … }
make_override = (vi) ->
  switch vi.verdict
    when "block"
      { kind: "block" }
    when "sinkhole"
      { kind: "sinkhole", a: vi.a, aaaa: vi.aaaa, ttl: vi.ttl }
    when "redirect"
      { kind: "redirect", cname_target: vi.cname_target, a: vi.a, aaaa: vi.aaaa, ttl: vi.ttl }
    else
      { kind: "pass" }

--- Process a DNS response packet from NFQUEUE.
-- Drains IPC, validates the transaction, patches TTL+checksums,
-- injects resolved IPs into nftables, and sets the verdict.
-- @tparam cdata  qh_ptr  nfq_q_handle pointer (for nfq_set_verdict)
-- @tparam cdata  nfad    nfq_data pointer
-- @tparam number pkt_id  NFQUEUE packet id
-- @treturn number NF_ACCEPT, NF_DROP, or -1 (verdict already set)
handle_response = (qh_ptr, nfad, pkt_id) ->
  bench_start_ms = if runtime_cfg.benchmark then current_benchmark_ms! else nil
  bench_after_drain_ms = nil
  bench_after_payload_ms = nil
  bench_after_parse_ms = nil
  bench_after_match_ms = nil

  -- ── Drain pipe IPC ───────────────────────────────────────────
  -- Absorbe tous les tokens disponibles de question avant de traiter ce paquet.
  -- Le callback update_mac_clients enrichit la table mac_clients au passage.
  ts = now!
  drain_ts = ts
  drain_pipe pipe_rfd, now, drain_on_msg
  bench_after_drain_ms = current_benchmark_ms! if runtime_cfg.benchmark

  -- ── Payload brut ─────────────────────────────────────────────
  payload_ptr = ffi.new "unsigned char*[1]"
  payload_len = libnfq.nfq_get_payload nfad, payload_ptr
  if payload_len <= 0
    return NF_DROP

  raw = ffi.string payload_ptr[0], payload_len
  bench_after_payload_ms = current_benchmark_ms! if runtime_cfg.benchmark

  -- ── L2 ────────────────────────────────────────────────────
  -- MAC source via nfq_get_packet_hw() ; MAC destination non exposée par libnfq.
  l2 = get_l2 nfad

  -- ── L3 / L4 / L7 ───────────────────────────────────────────────
  -- parse_packet gère IPv4 et IPv6, UDP et TCP, et le header DNS en un seul appel.
  ip, l4, dns_msg, dns_raw, ip_ihl = parse_packet raw
  bench_after_parse_ms = current_benchmark_ms! if runtime_cfg.benchmark
  unless ip
    -- Intermediate TCP data segments are DROPped so response can reinject a single
    -- coalesced+TTL-patched packet once the full DNS message is assembled.
    -- TCP control packets (SYN-ACK, pure ACK with no payload, FIN) return nil
    -- without "buffering" and must be passed through unchanged.
    return NF_DROP if l4 == "buffering"
    return NF_ACCEPT

  -- Purge périodique sans math.random (hot-path): compteur mod 1000
  purge_counter = (purge_counter + 1) % 1000
  if purge_counter == 0
    tcp_state.purge!
    purge_mac_clients ts

  unless dns_msg.header.qr
    return NF_ACCEPT

  -- La question originale avait src_ip=ip.dst, src_port=l4.dpt
  -- (la réponse est adressée au client LAN).
  src_ip      = ip2s ip.src
  dst_ip      = ip2s ip.dst
  client_port = l4.dpt
  txid        = dns_msg.header.id
  txid_hex    = string.format "0x%04x", txid
  client_ip   = dst_ip
  resolver_ip = src_ip
  -- MAC du client : resolution depuis la table ip_to_mac alimentée par question via IPC.
  -- mac_dst n'est jamais exposée par libnfq ; on utilise le reverse-lookup local.
  client_mac = ip_to_mac[client_ip] or "unknown"
  -- Utilisateur authentifié (nil si l'IP n'a pas de session valide)
  -- L'indexation par MAC permet de reconnaître un client authentifié
  -- en IPv6 quand ses paquets IPv4 arrivent (et vice-versa) de manière O(1).
  user        = user_for_mac client_mac, client_ip, auth_cfg.sessions_file or "/tmp/sessions.lua"

  -- ── Second avis : réponse provenant d'un validateur (src ∈ resolvers) ──
  -- Deux cas à distinguer via la présence d'une transaction IPC en attente :
  --  (a) AUCUNE transaction → réponse à NOTRE requête dupliquée (B pure) : sert
  --      au verdict puis NF_DROP (jamais transmise au client) ;
  --  (b) transaction présente → le DNS PRINCIPAL du client EST le validateur :
  --      la réponse est déjà filtrée à la source ; on la laisse suivre le chemin
  --      normal, SANS second avis (ni parking, ni drop) — sinon on casserait la
  --      résolution du client.
  direct_validator = false
  if so_state and so_state.is_validator resolver_ip
    if get_pending_entry txid, dst_ip, client_port, resolver_ip, now
      direct_validator = true
    else
      q1 = dns_msg.questions and dns_msg.questions[1]
      if q1
        key = so_state.corr_key client_ip, txid, q1.name
        override = make_override dns_classify.classify dns_msg, dns_raw
        parked_ctx = so_state.take_parked key
        if parked_ctx
          finalize_a parked_ctx, override
        else
          so_state.store_verdict key, override, ts
      return NF_DROP

  -- ── Vérification IPC ─────────────────────────────────────────
  entry = get_pending_entry txid, dst_ip, client_port, resolver_ip, now
  retry_attempts = 0
  retry_wait_ms = 0
  unless entry
    entry, retry_attempts, retry_wait_ms = retry_pending_match txid, dst_ip, client_port, resolver_ip
    if entry
      log_info -> {
        action: "response_matched_after_retry"
        src_ip: src_ip
        dst_ip: dst_ip
        txid: txid_hex
        retry_attempts: retry_attempts
        retry_wait_ms: retry_wait_ms
        user: user
      }
    else
      log_debug -> {
        action:    if retry_attempts > 0 then "response_no_matching_question_after_retry" else "response_no_matching_question"
        src_ip:    src_ip
        dst_ip:    dst_ip
        vlan:      l2.vlan
        txid:      txid_hex
        rcode:     dns_msg.header.rcode
        client_mac: client_mac
        retry_attempts: retry_attempts
        retry_wait_ms: retry_wait_ms
        user: user
      }
      return NF_DROP
  bench_after_match_ms = current_benchmark_ms! if runtime_cfg.benchmark

  -- ── Retry upstream sur réponse transitoirement en échec ──────────
  -- Avant de consommer/transmettre : si le résolveur a renvoyé SERVFAIL/REFUSED
  -- et que le budget d'essais n'est pas épuisé, réémettre la requête vers le même
  -- résolveur et DROP cette réponse. La transaction reste en attente : la réponse
  -- du retry repassera par ici et sera appariée à la même `entry`.
  if try_upstream_retry entry, dns_msg, dns_raw, ip, l4, resolver_ip
    q1 = dns_msg.questions and dns_msg.questions[1]
    log_debug -> {
      action:     "response_upstream_retry"
      src_ip:     src_ip
      dst_ip:     dst_ip
      vlan:       l2.vlan
      txid:       txid_hex
      qname:      q1 and q1.name or "-"
      rcode:      bit.band dns_msg.header.ra_z_rcode, 0x0f
      attempt:    entry.upstream_retries
      resolver:   resolver_ip
      client_mac: client_mac
      user:       user
    }
    return NF_DROP

  -- Transaction consommée (one-shot : une réponse par question)
  consume txid, dst_ip, client_port, resolver_ip

  -- Benchmark : quand activé, le verdict ALLOW/BLOCK est émis ICI (worker
  -- response), enrichi des temps, plutôt que côté question — pour réunir verdict
  -- et latence dans une seule ligne. La latence totale (`q_to_response_ms`,
  -- de l'entrée de la question au log de la réponse, traitement inclus) n'est
  -- connue qu'à ce stade ; `question_proc_ms` en isole la part traitement
  -- question, `response_entry_ms` la part sortie question→réponse. Le champ
  -- `action=dns_benchmark` (préfixé `response_`) évite le rate-limiting
  -- ALLOW/BLOCK (30 s) afin de conserver tous les échantillons. Le worker
  -- question supprime sa propre ligne ALLOW/BLOCK quand benchmark est actif.
  if runtime_cfg.benchmark and entry and entry.benchmark_ms
    bench_log_ms = current_benchmark_ms!
    delta_ms = bench_log_ms - entry.benchmark_ms
    if delta_ms >= 0
      q1 = dns_msg.questions and dns_msg.questions[1]
      info = {
        client_mac:  client_mac
        vlan:        l2.vlan
        client_ip:   client_ip
        resolver_ip: resolver_ip
        client_port: client_port
        txid:        txid
        af:          ip.version == 6 and "ipv6" or "ipv4"
        user:        user
        qname:       q1 and q1.name or "-"
        qtype:       q1 and (QTYPE[q1.qtype] or "TYPE#{q1.qtype}") or "-"
        retry_wait_ms:  retry_wait_ms
        retry_attempts: retry_attempts
      }
      -- entry.benchmark_ms = jalon d'ENTRÉE question : delta_ms couvre donc tout
      -- le traitement. La sortie question (base de response_entry_ms) est
      -- reconstituée : entrée + durée du traitement interne question.
      question_proc_ms = entry.question_proc_ms or 0
      q_exit_ms = entry.benchmark_ms + question_proc_ms
      deltas = {
        delta_ms:          delta_ms
        question_proc_ms:  question_proc_ms
        response_entry_ms: bench_delta bench_start_ms, q_exit_ms
        drain_ms:          bench_delta bench_after_drain_ms, bench_start_ms
        payload_ms:        bench_delta bench_after_payload_ms, bench_after_drain_ms
        parse_ms:          bench_delta bench_after_parse_ms, bench_after_payload_ms
        match_ms:          bench_delta bench_after_match_ms, bench_after_parse_ms
        log_ms:            bench_delta bench_log_ms, bench_after_match_ms
      }
      bench_fields, verdict = build_benchmark_fields entry, info, deltas
      if verdict == "block"
        log_block -> bench_fields
      else
        log_allow -> bench_fields

  refused = entry and entry.refused or false
  dnsonly = entry and entry.dnsonly or false
  nft_rule_id = (entry and entry.rule_id and #entry.rule_id > 0) and entry.rule_id or "unknown_rule"
  ack_corr = string.format "%04x:%s:%d:%s", txid, dst_ip, client_port, resolver_ip

  -- ── Branche REFUSED/NXDOMAIN : réponse du serveur transformée ──────
  if refused
    nxdomain_mod = entry.modifiers and entry.modifiers.nxdomain
    refused_dns = if nxdomain_mod
      build_nxdomain_response dns_msg, dns_raw, entry.reason
    else
      build_blocked_response dns_msg, dns_raw, entry.reason
    unless refused_dns
      return NF_DROP
    refused_dns = strip_https_rr(refused_dns) or refused_dns
    patched = replace_dns_payload raw, ip, l4, ip_ihl, refused_dns
    unless patched
      return NF_DROP
    qnames = table.concat [q.name for q in *dns_msg.questions], ","
    log_debug -> {
      action:   nxdomain_mod and "response_nxdomain" or "response_refused"
      src_ip:   src_ip
      dst_ip:   dst_ip
      vlan:     l2.vlan
      txid:     txid_hex
      qnames:   qnames
      client_mac: client_mac
      user:     user
    }
    patched_ptr = ffi.cast "const unsigned char*", patched
    libnfq.nfq_set_verdict qh_ptr, pkt_id, NF_ACCEPT, #patched, patched_ptr
    return -1

  -- ── Branche ACCEPT : second avis puis finalisation ────────────
  -- Contexte paquet capturé pour finalize_a (appel en ligne ou au déparquage).
  ctx = {
    :qh_ptr, :pkt_id, :raw, :ip, :l4, :ip_ihl, :dns_msg, :dns_raw, :entry
    :resolver_ip, :dnsonly, :nft_rule_id, :ack_corr
    :client_ip, :client_mac, :user, :txid
    vlan: l2.vlan, :src_ip, :dst_ip
  }

  -- Second avis : corrélation avec la réponse validateur (B) uniquement si la
  -- règle porte l'action `validate`.
  --   • verdict déjà connu  → appliquer immédiatement (block/redirect/pass) ;
  --   • verdict pas encore là → parquer A (verdict NFQUEUE différé) jusqu'à B
  --     ou expiration du budget (fail-open, balayé par sweep_parked).
  do_so = entry and entry.modifiers and entry.modifiers.validate
  q1 = dns_msg.questions and dns_msg.questions[1]
  if so_state and q1 and do_so and so_state.active_for(ip.version) and not direct_validator
    key = so_state.corr_key client_ip, txid, q1.name
    override = so_state.take_verdict key, ts
    if override
      finalize_a ctx, override
    else
      so_state.park key, ctx, current_benchmark_ms!
    return -1

  -- Second avis désactivé (ou pas de question) : chemin normal immédiat.
  finalize_a ctx, nil
  -1   -- sentinel : finalize_a a posé le verdict


-- ── Point d'entrée ───────────────────────────────────────────────
--- Start the response worker.
-- Blocks in the NFQUEUE loop until the process exits.
-- @tparam number rfd Read end of the IPC pipe from question.
-- @tparam table rules_metadata Rules metadata passed from main.moon to avoid recompiling
run = (queue_num, rfd, rules_metadata) ->
  set_action_prefix "response_"
  load_auth_wildcard_rules rules_metadata if rules_metadata
  if type(rfd) == "table"
    nft_q = require "nft_queue"
    nft_q.set_wfd rfd.nft_wfd if rfd.nft_wfd
    -- Configure le canal ACK bidirectionnel si le superviseur en a alloué un.
    nft_q.set_ack_rfd rfd.ack_rfd, rfd.worker_idx if rfd.ack_rfd and rfd.worker_idx != nil
    rfd = rfd.question_response_rfd
  pipe_rfd = rfd
  -- Pré-remplit mac_clients / ip_to_mac depuis la table ARP/NDP courante,
  -- avant même la première requête DNS. Indispensable pour le cross-family
  -- (IPv6 client → RR A) quand aucun message IPC n'a encore été reçu.
  -- mac_clients et ip_to_mac démarrent vides ; ils sont alimentés organiquement
  -- par les messages IPC reçus de question (update_mac_clients dans drain_on_msg).

  -- ── Second avis DNS ────────────────────────────────────────────
  -- Activé si enabled + au moins un résolveur. Le worker_questions duplique les
  -- questions ; ici on corrèle les deux réponses. Le balayage du budget se fait
  -- via le timeout poll de run_queue (sweep_parked).
  -- Familles actives = celles dont un validateur est routable (même probe que
  -- worker_questions). Une famille non routable (ex. IPv6 sans tunnel) ne doit
  -- jamais être parquée, sinon chaque réponse de cette famille attendrait le
  -- budget pour rien.
  -- Collecte tous les résolveurs validateurs : globaux + per-règle.
  -- Nécessaire pour que is_validator reconnaisse les réponses de validateurs
  -- per-règle et les corrèle correctement.
  collect_all_resolvers = ->
    seen = {}
    all = {}
    add = (r) ->
      unless seen[r]
        seen[r] = true
        all[#all + 1] = r
    add r for r in *(so_cfg.resolvers or {})
    for meta in *(rules_metadata or {})
      add r for r in *(meta.validate_resolvers or {})
    all

  -- Sockets RAW (HDRINCL) pour le retry upstream : un par famille, best-effort.
  -- La réémission vise le résolveur du client (routable par construction).
  if retry_enabled
    arm_retry_fds!
    log_info -> { action: "dns_upstream_retry_armed", max_attempts: retry_max, ipv4: retry_fds.ipv4 != nil, ipv6: retry_fds.ipv6 != nil }

  local run_opts
  all_resolvers = collect_all_resolvers!
  if #all_resolvers > 0
    families = {}
    for fam, ver in pairs { ipv4: 4, ipv6: 6 }
      v_ip = dup_query.pick_resolver all_resolvers, ver
      families[fam] = (v_ip and raw_send.routable(ver, v_ip)) and true or false
    if families.ipv4 or families.ipv6
      so_state = second_opinion.new {
        resolvers:    all_resolvers
        budget_ms:    so_cfg.budget_ms or 80
        verdict_ttl_s: 5
        :families
      }
      run_opts = { idle_ms: so_cfg.budget_ms or 80, on_idle: sweep_parked }
      log_info -> { action: "dns_validator_responses_armed", resolvers: table.concat(all_resolvers, ","), ipv4: families.ipv4, ipv6: families.ipv6 }

  run_queue tonumber(queue_num), handle_response, run_opts

{ :run, :rr_timeout, :patch_modified_dns, :bench_delta, :build_benchmark_fields,
  :skip_ipv6_ext_hdrs, :dns_tcp_complete, :new_dns_tcp_stream,
  :try_upstream_retry, :arm_retry_fds }
