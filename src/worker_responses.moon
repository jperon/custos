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
{ :parse_dns, :ip2s, dns_types: QTYPE } = require "lib.packet_parsing"
{ :skip_ipv6_ext_hdrs, :new_dns_tcp_stream, :parse_dns_packet } = require "packet_utils"
{ :get_l2 } = require "nfq/ethernet"
{ :drain_pipe, :is_pending, :get_pending_entry, :consume, :purge_pending } = require "ipc"
{ :add_ip4_many, :add_ip6_many, :add_mac4_many, :add_mac6_many, :add_mac4, :add_mac6, :get_last_seq, :wait_ack, :drain_ack } = require "nft_queue"
{ :run_queue, :NF_ACCEPT, :NF_DROP, :MAX_BATCH_PKTS, :packet_age_ms } = require "nfq_loop"
{ :log_info, :log_warn, :log_debug, :log_allow, :log_block, :now, :set_action_prefix, :level_enabled, :get_last_write_us } = require "log"
{ :tsv_field } = require "lib.tsv"
{ :build_blocked_response, :build_nxdomain_response, :build_sinkhole_response, :build_cname_response, :strip_https_rr, :strip_dns_rr, :add_ede_modified, :clear_ad_bit, :patch_modified_dns } = require "dns_ede"
strip_codec = require "strip_codec"
mac_ipc     = require "mac_learner_ipc"

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

-- Identifiant (préfixe) des sets nft `captive_probe_mac4/6` : destinations des
-- réponses `dnsonly` (sondes de portail captif), consommées par une règle nft
-- placée AVANT le dispatch. Voir finalize_a et docs/agents/filtre.md.
CAPTIVE_PROBE_SET = "captive_probe"

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

-- fd d'écriture du pipe « events » (alimente worker_events / recent-verdicts).
-- Initialisé dans run() depuis rfd.events_wfd. Permet de signaler les blocages
-- décidés par le validateur amont (override block/sinkhole), invisibles sinon
-- car write_event de worker_questions a déjà loggé la requête en « allow ».
events_wfd = nil

-- ── Strip DNS contextuel à la chaîne CNAME ──────────────────────────
-- Quand un résolveur (ex. systemd-resolved) chase lui-même la chaîne CNAME et
-- émet une question TERMINALE séparée (qui échappe au `to_domains` de la
-- règle d'origine), on mémorise les cibles CNAME observées au moment du strip
-- (record_chain_targets, alimente le pipe `strip_learn_wfd` → mac_learner) et
-- on les ré-interroge à chaque réponse (maybe_dynamic_strip, via
-- mac_learner_ipc.strip_target) pour appliquer le même strip côté terminal.
-- Gating strict : si chain_strip_enabled est false, ni IPC ni écriture pipe.
chain_strip_enabled = false
strip_learn_wfd     = nil
strip_query_cache   = {}   -- { qname → { rr_code|false, expires_epoch } }
STRIP_QUERY_TTL      = 2

--- Émet un message learn par cible CNAME de la réponse (fonction pure : ne
-- touche aucune upvalue, le gating se fait à l'appel dans finalize_a).
-- @tparam table    dns     Message DNS parsé (answers).
-- @tparam string   dns_raw Payload brut (décompression des noms).
-- @tparam number   rr_code Type DNS à stripper (ex. 28 = AAAA).
-- @tparam function send_fn Reçoit chaque message encodé (écriture pipe en prod).
-- @treturn nil
record_chain_targets = (dns, dns_raw, rr_code, send_fn) ->
  return unless dns and dns_raw and rr_code and send_fn
  for target in *dns_classify.cname_targets dns, dns_raw, 1
    send_fn strip_codec.encode target, rr_code

--- Applique un strip dynamique si qname est une cible apprise (cache TTL
-- positif et négatif pour borner les appels IPC).
-- @tparam string   qname    Nom de la question courante.
-- @tparam string   dns_raw  Payload DNS brut de la réponse.
-- @tparam function lookup_fn Typiquement mac_learner_ipc.strip_target.
-- @treturn string  dns_raw (modifié ou non)
-- @treturn boolean modified
maybe_dynamic_strip = (qname, dns_raw, lookup_fn) ->
  return dns_raw, false unless qname and dns_raw and lookup_fn
  now_ts = os.time!
  cached = strip_query_cache[qname]
  rr_code = if cached and now_ts <= cached[2]
    cached[1]
  else
    v = lookup_fn qname
    strip_query_cache[qname] = { v or false, now_ts + STRIP_QUERY_TTL }
    v
  return dns_raw, false unless rr_code
  stripped = strip_dns_rr dns_raw, rr_code
  return dns_raw, false if stripped == dns_raw
  stripped = add_ede_modified(stripped, "Strip by CNAME chain context") or stripped
  (clear_ad_bit stripped), true

--- Purge les entrées de strip_query_cache expirées. Sans cet appel
-- périodique, chaque nom de domaine interrogé une seule fois (CDN,
-- sous-domaines uniques, tracking) laisse une entrée en mémoire pour
-- toujours dès que chain_strip_enabled est actif (croissance non bornée).
-- @tparam number now_ts Temps courant (secondes)
purge_strip_query_cache = (now_ts) ->
  for qname, entry in pairs strip_query_cache
    strip_query_cache[qname] = nil if now_ts > entry[2]


--- Formate une ligne d'événement « block » validateur (fonction pure).
-- Même format que worker_questions.write_event : ts<TAB>decision<TAB>qname
-- <TAB>mac_src<TAB>src_ip<TAB>dst_ip<TAB>vlan<TAB>user<TAB>af<TAB>reason<TAB>rule<LF>.
-- @tparam table  ctx Contexte paquet de finalize_a (qname, client_mac, af, …)
-- @tparam number ts  Timestamp (secondes) ; défaut os.time!
-- @treturn string Ligne TSV terminée par un \n
format_block_event = (ctx, ts=os.time!) ->
  table.concat({
    tostring ts
    "block"
    tsv_field ctx.qname
    tsv_field ctx.client_mac
    tsv_field ctx.src_ip
    tsv_field ctx.dst_ip
    tsv_field ctx.vlan
    tsv_field ctx.user
    tsv_field ctx.af
    VALIDATOR_REASON
    tsv_field ctx.nft_rule_id
  }, "\t") .. "\n"

--- Signale un blocage validateur à worker_events (best-effort).
-- @tparam table ctx Contexte paquet de finalize_a
-- @treturn nil
write_block_event = (ctx) ->
  return unless events_wfd
  line = format_block_event ctx
  libc.write events_wfd, line, #line

-- Helper : pose un verdict NFQUEUE avec payload optionnel.
set_verdict = (qh_ptr, pkt_id, verdict, payload=nil) ->
  if payload
    ptr = ffi.cast "const unsigned char*", payload
    libnfq.nfq_set_verdict qh_ptr, pkt_id, verdict, #payload, ptr
  else
    libnfq.nfq_set_verdict qh_ptr, pkt_id, verdict, 0, nil

tcp_state = new_dns_tcp_stream!

-- Reconstruction de paquet et formatage des RR DNS factorisés (fonctions pures).
{ :replace_dns_payload, :parse_answers, :build_query_from_response } = require "lib.dns_response"

-- ── Parsing L3/L4/L7 ────────────────────────────────────────────

-- Parsing partagé avec worker_questions (cf. packet_utils) : ip, l4, dns_msg,
-- dns_raw, ip_ihl. Retourne nil, "status" sur les cas spéciaux.

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

-- ── Budget de retry d'appariement IPC ────────────────────────────────
-- Le retry existe pour absorber un réordonnancement IPC légitime : la réponse
-- du résolveur peut être recapturée (et traitée) avant que le worker questions
-- n'ait écrit/été drainé sur le pipe `question_response`. Ce réordonnancement
-- se compte en microsecondes à quelques millisecondes (la question est écrite
-- avant le forward upstream ; le RTT upstream, lui, se compte en ms) : la
-- PREMIÈRE tentative (sleep_ms) suffit dans le cas nominal.
-- Sans borne, une rafale de réponses orphelines sérialisait le worker dans le
-- hot-path NFQ : `count` (5) × `sleep_ms` (20) = 100 ms par réponse, soit
-- ~10 réponses/s de débit et 100 % de temps passé en nanosleep — un vecteur
-- de déni de service local.
-- Budget : au plus `budget_ms` de sommeil par seconde et par worker, toutes
-- réponses confondues (fenêtre = seconde d'epoch courante). Choisi à 100 ms
-- (10 % de temps au pire, jamais atteint par le cas nominal qui consomme
-- 20 ms) : le budget autorise encore les 5 tentatives d'une seule réponse
-- (comportement historique préservé pour un réordonnancement isolé) tout en
-- faisant tomber immédiatement les orphelins suivants (aucun nanosleep,
-- drop direct). Un réordonnancement isolé consomme 20 ms, soit 5 événements
-- par seconde absorbés pleinement.
RETRY_BUDGET_MS = if match_retry_cfg.budget_ms == nil then 100 else match_retry_cfg.budget_ms
_retry_budget = { second: -1, used_ms: 0 }

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

-- Bus de verdicts « second avis » entre workers réponses (multi-worker) :
-- `so_bus_rfd` = pipe que CE worker lit, `so_bus_wfds` = pipes de TOUS les
-- workers réponses (fan-out). Nil à un seul worker : aucun coût.
so_bus_rfd  = nil
so_bus_wfds = nil
so_bus_buf  = ""
SO_BUS_CHUNK = 1024
so_bus_read_buf = ffi.new "uint8_t[?]", SO_BUS_CHUNK

sleep_req = ffi.new "timespec_t[1]"
CLOCK_MONOTONIC = 1

-- Compteur de purge périodique (hot-path, sans math.random) : déclenche
-- tcp_state.purge et purge_mac_clients tous les 1000 paquets.
purge_counter = 0

-- Drain du tube IPC déclenché par le poll (on_extra_ready, sans paquet
-- NFQUEUE) : compteur de réveils depuis la dernière purge des entrées `pending`
-- expirées. Un worker dont la file NFQUEUE ne reçoit aucun paquet ne passe
-- jamais par la purge de `handle_response` (compteur mod 1000) : sans celle-ci,
-- les entrées absorbées resteraient jusqu'à l'éviction `ipc.pending_max`
-- (cf. docs/agents/perf.md §12). La purge est en O(pending) : la borner.
DRAIN_PURGE_EVERY = 64
drain_purge_counter = 0

-- Benchmark : buffer timespec réutilisé
_benchmark_ts = ffi.new "timespec_t[1]"

--- Retourne les millisecondes depuis boot (CLOCK_MONOTONIC).
-- @treturn number
current_benchmark_ms = ->
  libc.clock_gettime CLOCK_MONOTONIC, _benchmark_ts
  tonumber(_benchmark_ts[0].tv_sec) * 1000 + math.floor(tonumber(_benchmark_ts[0].tv_nsec) / 1000000)

--- Retourne les microsecondes depuis boot (CLOCK_MONOTONIC).
-- Résolution µs entière : les jalons en ms (plancher 1 ms) masqueraient une
-- attente d'ACK habituellement sous la milliseconde ; c'est la queue de
-- distribution qui nous intéresse. Utilisée uniquement en mode benchmark.
-- @treturn number
current_benchmark_us = ->
  libc.clock_gettime CLOCK_MONOTONIC, _benchmark_ts
  tonumber(_benchmark_ts[0].tv_sec) * 1000000 + math.floor(tonumber(_benchmark_ts[0].tv_nsec) / 1000)

-- Dernière attente d'ACK mesurée (µs) sur ce worker, à consommer par la
-- prochaine ligne benchmark. L'ACK est posé APRÈS l'émission du log de la
-- transaction : la valeur ne peut donc pas figurer dans la ligne de LA
-- transaction qui attend. Elle est reportée sur la ligne suivante (cf.
-- take_last_ack_wait_us) et remise à zéro une fois consommée.
_last_ack_wait_us = 0

--- Rend la dernière attente d'ACK mesurée (µs) et remet le compteur à zéro.
-- @treturn number durée en µs (0 si aucun wait_ack depuis la dernière prise)
take_last_ack_wait_us = ->
  v = _last_ack_wait_us
  _last_ack_wait_us = 0
  v

--- Exécute `wait_ack` en mesurant sa durée en microsecondes (mode benchmark).
-- Hors benchmark, appelle directement `wait_ack` : aucun appel d'horloge
-- supplémentaire sur le chemin nominal. La durée mesurée est mémorisée pour
-- la ligne benchmark SUIVANTE (l'ACK de la transaction courante est postérieur
-- à son propre log) : mesure parallèle, non additive.
-- @tparam number pending_seq Seq à acquitter (cf. nft_queue.wait_ack)
-- @tparam string corr        Corrélateur d'ACK
-- @tparam function|nil on_wait Callback de drain intercalé
-- @treturn boolean true si l'ACK attendu est arrivé dans le budget
measured_wait_ack = (pending_seq, corr, on_wait) ->
  unless runtime_cfg.benchmark
    return wait_ack pending_seq, corr, on_wait
  t0 = current_benchmark_us!
  ok = wait_ack pending_seq, corr, on_wait
  _last_ack_wait_us = current_benchmark_us! - t0
  ok

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
-- @tparam table entry  Transaction IPC (refused, reason, rule_id, dnsonly,
--                      upstream_retries)
-- @tparam table info   Métadonnées : client_mac, vlan, client_ip, resolver_ip,
--                      client_port, txid, af, user, qname, qtype, ipc_retry_*
-- @tparam table deltas Jalons : delta_ms (→ q_to_response_ms), question_proc_ms,
--                      response_entry_ms, drain_ms, payload_ms, parse_ms, match_ms, log_ms,
--                      ack_wait_us, log_write_us
-- @treturn table  Champs prêts pour log_allow/log_block
-- @treturn string Verdict : "block" si entry.refused, sinon "allow"
-- ATTENTION — `ack_wait_us` est une mesure PARALLÈLE, NON ADDITIVE :
-- `wait_ack` intervient APRÈS l'émission de cette ligne et APRÈS
-- `set_verdict`, donc hors de la chaîne
-- q_to_response_ms = question_proc_ms + response_entry_ms + drain_ms +
-- payload_ms + parse_ms + match_ms + log_ms (invariant à résidu nul vérifié
-- en production). Ne jamais l'ajouter à cette somme.
-- `log_write_us` mesure le `libc.write` du journal (coût bloquant potentiel),
-- et non la construction des champs : voir doc/CONFIG.md.
-- Les deux familles de retry sont distinctes et ne doivent pas être confondues :
--   * `ipc_retry_*` : retry d'APPARIEMENT IPC (la réponse est arrivée avant que
--     la question ne soit lue du pipe) — mesuré localement, coût Custos ;
--   * `upstream_retries` : nombre de renvois de la requête vers le résolveur
--     amont (`try_upstream_retry`, `entry.upstream_retries`) — 0 si aucun.
--     Seul un compteur existe (aucune durée n'est stockée) : ne pas inventer de
--     `upstream_wait_ms`.
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
    -- Mesures µs non additives (cf. avertissement ci-dessus).
    ack_wait_us:   deltas.ack_wait_us or 0
    log_write_us:  deltas.log_write_us or 0
    ipc_retry_wait_ms:  info.ipc_retry_wait_ms
    ipc_retry_attempts: info.ipc_retry_attempts
    upstream_retries:   entry.upstream_retries or 0
  }
  fields, (entry.refused and "block" or "allow")

update_mac_clients = nil
drain_ts = 0
drain_on_msg = (msg) ->
  update_mac_clients msg, drain_ts

-- ── Verdicts différés par lot NFQUEUE ────────────────────────────────
-- Un lot = tous les paquets d'une même lecture netlink (cf. nfq_loop.run_queue,
-- option on_batch_end). Sous charge, attendre l'ACK nft de CHAQUE réponse coûte
-- un aller-retour resp-q* → worker nft par réponse (31 % du temps mural du
-- worker à 200 q/s, ACK p99 8-13 ms : cf. docs/agents/perf.md). On enfile donc
-- les insertions de tout le lot, on attend UNE fois le plus grand seq, puis on
-- pose les verdicts : aucun paquet n'est rendu au client avant que les IP du
-- lot soient dans les sets nft (invariant de sécurité inchangé).
deferred = {}
defer_deps = nil

--- Dépendances du chemin de verdict (injectables en test unitaire).
-- @treturn table { get_last_seq, wait_ack, set_verdict }
verdict_deps = ->
  defer_deps or {
    get_last_seq: get_last_seq
    wait_ack:     measured_wait_ack
    set_verdict:  set_verdict
  }

--- Nombre de verdicts en attente de l'ACK du lot courant.
-- @treturn number
deferred_count = -> #deferred

--- Remplace les dépendances du chemin de verdict (tests unitaires uniquement).
-- @tparam table|nil deps { get_last_seq, wait_ack, set_verdict } ou nil
-- @treturn nil
_set_defer_deps = (deps) ->
  defer_deps = deps
  nil

--- Vide la file de verdicts différés (tests unitaires uniquement).
-- @treturn nil
_reset_deferred = ->
  deferred = {}
  nil

--- Attend l'ACK nft du dernier seq enfilé par un lot puis pose ses verdicts.
-- Pendant l'attente, `read_packets` (fourni par nfq_loop) lit et traite les
-- paquets arrivés dans la file : leurs verdicts s'accumulent dans `deferred`,
-- donc dans le lot SUIVANT, et ne sont pas posés ici. La lecture est bornée à
-- MAX_BATCH_PKTS au total par attente : le lot suivant garde la borne de
-- `nfq_loop` (mémoire et latence).
-- @tparam table         batch        Verdicts à poser
-- @tparam table         deps         Dépendances du chemin de verdict
-- @tparam function|nil  read_packets Lecture non bloquante (nil = aucune)
-- @treturn nil
_flush_batch = (batch, deps, read_packets) ->
  pending_seq = deps.get_last_seq!
  if pending_seq
    budget = MAX_BATCH_PKTS
    on_wait = ->
      drain_pipe pipe_rfd, now, drain_on_msg if pipe_rfd
      if read_packets and budget > 0
        budget -= read_packets budget
    deps.wait_ack pending_seq, (batch[#batch].corr or ""), on_wait
  for rec in *batch
    deps.set_verdict rec.qh_ptr, rec.pkt_id, rec.verdict, rec.payload
  nil

--- Attend l'ACK nft des insertions du lot puis pose les verdicts différés.
-- `get_last_seq` retourne le plus grand seq enfilé depuis le dernier prélèvement
-- (toutes transactions du lot confondues, cf. nft_queue.get_last_seq) : l'ACK de
-- ce seq prouve que toutes les insertions du lot sont appliquées. Un timeout
-- conserve le comportement historique (verdicts posés, avertissement déjà émis
-- par nft_queue.wait_ack) : le client ne reçoit pas davantage de droits, il
-- peut seulement résoudre une IP pas encore autorisée.
-- Pendant l'attente, les paquets lus (`read_packets`) forment un lot SUIVANT,
-- dont les verdicts ne sont posés qu'après SON PROPRE ACK (plus grand seq
-- enfilé par ces paquets) : ils ne peuvent donc pas hériter de l'ACK du lot
-- courant, qui ne couvre pas leurs insertions. Aucune lecture pendant la
-- seconde attente (pas de récursion) : les paquets restants sont lus par la
-- boucle principale.
-- @tparam[opt] function|nil read_packets Lecture non bloquante fournie par
--                                          nfq_loop (nil à la sortie de boucle)
-- @treturn number Nombre de verdicts posés
flush_deferred = (read_packets) ->
  n = #deferred
  return 0 if n == 0
  deps = verdict_deps!
  posed = 0
  -- pcall : le flush tourne hors du wrapper pcall du callback NFQUEUE ; une
  -- erreur inattendue ne doit pas tuer le worker (les paquets du lot seraient
  -- alors perdus à la destruction de la queue, donc fail-closed).
  ok, err = pcall ->
    batch = deferred
    deferred = {}
    posed = #batch
    _flush_batch batch, deps, read_packets
    if #deferred > 0
      nxt = deferred
      deferred = {}
      posed += #nxt
      _flush_batch nxt, deps, nil
  unless ok
    log_warn -> { action: "deferred_flush_error", count: posed, err: tostring err }
  posed

--- Pose — ou différe — le verdict final d'une réponse (appelé par finalize_a).
-- En mode lot (`ctx.defer`), le verdict est mémorisé pour `flush_deferred` et
-- aucune attente d'ACK n'est faite ici. Hors lot (déparking du second avis,
-- tests), le comportement d'origine est conservé : attente si `need_ack`, puis
-- verdict immédiat.
-- @tparam table      ctx      Contexte paquet (qh_ptr, pkt_id, ack_corr, dnsonly)
-- @tparam number     verdict  NF_ACCEPT | NF_DROP
-- @tparam string|nil payload  Payload de remplacement éventuel
-- @tparam boolean    need_ack true si des insertions nft doivent être acquittées
-- @treturn nil
settle = (ctx, verdict, payload, need_ack) ->
  if ctx.defer
    deferred[#deferred + 1] = {
      qh_ptr:  ctx.qh_ptr
      pkt_id:  ctx.pkt_id
      :verdict
      :payload
      corr:    ctx.ack_corr
    }
    return
  deps = verdict_deps!
  -- `need_ack` est vrai dès qu'une insertion (accès ou captive_probe) a été
  -- enfilée, y compris pour une réponse dnsonly (cf. finalize_a).
  if need_ack
    pending_seq = deps.get_last_seq!
    deps.wait_ack pending_seq, ctx.ack_corr, (-> drain_pipe pipe_rfd, now, drain_on_msg) if pending_seq
  deps.set_verdict ctx.qh_ptr, ctx.pkt_id, verdict, payload

sleep_ms = (ms) ->
  return unless ms and ms > 0
  sleep_req[0].tv_sec = math.floor ms / 1000
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  libc.nanosleep sleep_req, nil

--- Nombre de tentatives autorisées par le budget de retry (fonction pure).
-- @tparam number used_ms   Millisecondes déjà consommées dans la fenêtre
-- @tparam number budget_ms Budget de sommeil par fenêtre
-- @tparam number wait_ms   Coût d'une tentative (sleep_ms)
-- @tparam number tries     Tentatives demandées par la configuration
-- @treturn number 0..tries ; 0 = budget épuisé (sauter le retry)
plan_retry_tries = (used_ms, budget_ms, wait_ms, tries) ->
  -- sleep_ms <= 0 : la tentative ne coûte qu'un drain (non bloquant), le
  -- budget de SOMMEIL ne s'applique pas — préserver le comportement historique.
  return tries if wait_ms <= 0
  return 0 unless budget_ms > 0
  remaining = budget_ms - (used_ms or 0)
  return 0 if remaining < wait_ms
  n = math.floor remaining / wait_ms
  if n < tries then n else tries

--- Vrai si un retry d'appariement IPC peut encore aboutir (fonction pure).
-- Une réponse plus vieille que `pending_ttl` ne peut plus être appariée : la
-- transaction, écrite dans le tube AVANT que la question ne parte en amont, a
-- été drainée (ou purgée) depuis longtemps. Sauter le retry évite jusqu'à
-- `count × sleep_ms` de sommeil par réponse orpheline (100 ms par défaut),
-- coût qui n'a aucune chance d'aboutir (cf. docs/agents/perf.md §17.9).
-- @tparam number|nil age_ms Âge noyau de la réponse (nil = inconnu)
-- @tparam number|nil ttl_s  Durée de vie d'une entrée pending (s)
-- @treturn boolean true si le retry reste utile
retry_worthwhile = (age_ms, ttl_s) ->
  return true unless age_ms
  return true unless ttl_s and ttl_s > 0
  age_ms <= ttl_s * 1000

--- Retry d'appariement IPC (réponse arrivée avant la lecture de la question).
-- Coût borné par `RETRY_BUDGET_MS` par seconde (cf. ci-dessus) : au-delà, le
-- retry est SAUTÉ (aucun nanosleep) et la réponse est traitée comme orpheline.
-- @tparam number txid         ID de transaction DNS
-- @tparam string client_ip    IP du client (dst de la réponse)
-- @tparam number client_port  Port source du client
-- @tparam string resolver_ip  IP du résolveur (src de la réponse)
-- @tparam number|nil ts       Epoch courant déjà connu de l'appelant (évite un
--                             appel d'horloge supplémentaire)
-- @treturn table|nil entry    Transaction appariée, ou nil
-- @treturn number   attempts   Tentatives effectuées
-- @treturn number   wait_ms    Sommeil cumulé réellement consommé (ms)
-- @treturn boolean  budget_skipped true si le retry a été sauté faute de budget
retry_pending_match = (txid, client_ip, client_port, resolver_ip, ts) ->
  return nil, 0, 0, false unless IPC_RETRY_ENABLED
  tries = IPC_RETRY_COUNT or 0
  wait_ms = IPC_RETRY_SLEEP_MS or 0
  return nil, 0, 0, false if tries <= 0

  now_s = ts or now!
  if now_s != _retry_budget.second
    _retry_budget.second = now_s
    _retry_budget.used_ms = 0

  allowed = plan_retry_tries _retry_budget.used_ms, RETRY_BUDGET_MS, wait_ms, tries
  return nil, 0, 0, true if allowed <= 0

  total_wait_ms = 0
  for i = 1, allowed
    sleep_ms wait_ms
    _retry_budget.used_ms += wait_ms
    total_wait_ms += wait_ms
    loop_ts = now!
    drain_ts = loop_ts
    drain_pipe pipe_rfd, now, drain_on_msg
    entry = get_pending_entry txid, client_ip, client_port, resolver_ip, now
    return entry, i, total_wait_ms, false if entry

  nil, allowed, total_wait_ms, false

-- ── Suivi des clients par adresse MAC ───────────────────────────
-- Mise à jour de mac_clients et ip_to_mac à chaque message IPC reçu.
-- Appelé en callback depuis drain_pipe.
--- Retire ip_to_mac[ip] seulement s'il désigne encore cette MAC.
-- Sans cette garde, l'expiration/changement d'IP de l'ancien propriétaire
-- effacerait le mapping du nouveau propriétaire de la même IP.
-- @tparam string|nil ip  Adresse IP mappée
-- @tparam string mac      MAC propriétaire présumée
forget_ip_mapping = (ip, mac) ->
  ip_to_mac[ip] = nil if ip and ip_to_mac[ip] == mac

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
      forget_ip_mapping entry.ipv4, mac
      entry.ipv4 = msg.ip_str
      ip_to_mac[msg.ip_str] = mac
  else                        -- MSG_IPV6
    unless entry.ipv6 == msg.ip_str
      forget_ip_mapping entry.ipv6, mac
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
      forget_ip_mapping entry.ipv4, mac
      forget_ip_mapping entry.ipv6, mac
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

-- Tables d'addition précalculées : créées une fois par processus au lieu
-- d'une par paquet dans finalize_a (cf. docs/agents/perf.md §22).
ADD_IP  = { ipv4: add_ip4_many, ipv6: add_ip6_many }
ADD_MAC = { ipv4: add_mac4_many, ipv6: add_mac6_many }

--- Résout l'adresse d'un client pour une famille (memoïsée dans ctx).
-- Fonction de module : remplace la closure `client_addr` recréée à chaque
-- paquet par finalize_a. Le memo tient dans le ctx (un par paquet).
-- @tparam table ctx Contexte paquet (client_ip, ip, _client_v4/_client_v6)
-- @tparam string fam "ipv4" ou "ipv6"
-- @treturn string|nil Adresse dans la famille demandée, ou nil
client_addr_of = (ctx, fam) ->
  if fam == "ipv4"
    ctx._client_v4 or= (ctx.ip.version == 4 and ctx.client_ip or resolve_client_family ctx.client_ip, "ipv4")
    ctx._client_v4
  else
    ctx._client_v6 or= (ctx.ip.version == 6 and ctx.client_ip or resolve_client_family ctx.client_ip, "ipv6")
    ctx._client_v6

--- Injecte des réponses A/AAAA (corps de l'ancienne closure inject_answers).
-- @tparam table ctx          Contexte paquet (defer)
-- @tparam table inject_opts  Options response_inject.inject
-- @tparam table answers      Liste { family, addr, ttl }
-- @treturn table Résultat inject
inject_answers = (ctx, inject_opts, answers) ->
  -- En cours de lot, purger les ACK est inutile (le flush du lot les lit) et
  -- peut jeter l'ACK de la dernière insertion du lot : cf. nft_queue.last_acked_seq.
  drain_ack! unless ctx.defer
  inject answers, inject_opts

--- Helper override : strip HTTPS/SVCB, repatche le paquet et pose le verdict
-- (NF_DROP si la construction ou le patch échoue). Le verdict peut être
-- différé à la fin du lot NFQUEUE (cf. settle). Corps de l'ancienne closure
-- patch_and_accept, en paramètres explicites.
-- @tparam table  ctx         Contexte paquet (raw, ip, l4, ip_ihl, …)
-- @tparam string new_dns     Payload de remplacement (ou nil)
-- @tparam string action_label Action du log DEBUG
-- @tparam string txid_hex    Txid formaté (déjà calculé par l'appelant)
-- @treturn nil
patch_and_accept = (ctx, new_dns, action_label, txid_hex) ->
  if new_dns
    new_dns = strip_https_rr(new_dns) or new_dns
    patched = replace_dns_payload ctx.raw, ctx.ip, ctx.l4, ctx.ip_ihl, new_dns
    if patched
      if level_enabled "DEBUG"
        log_debug -> { action: action_label, src_ip: ctx.src_ip, dst_ip: ctx.dst_ip, txid: txid_hex, client_mac: ctx.client_mac, user: ctx.user }
      return settle ctx, NF_ACCEPT, patched, false
  settle ctx, NF_DROP, nil, false

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

  -- Résolveur d'adresse client par famille (memoïsé dans ctx, cf.
  -- client_addr_of) : une closure à 1 upvalue au lieu de 3 closures lourdes.
  client_addr = (fam) -> client_addr_of ctx, fam

  -- Options inject partagées (réutilisées avec inject_nft ajusté plus bas).
  inject_opts = {
    :client_addr, :client_mac, :user
    rule_id:      nft_rule_id
    wildcard_ids: auth_wildcard_rules
    :ack_corr
    inject_nft:   true
    :mac_valid
    add_ip:  ADD_IP
    add_mac: ADD_MAC
  }

  -- ── Override : blocage NXDOMAIN + EDE (Filtered) ──────────────
  if override and override.kind == "block"
    write_block_event ctx
    return patch_and_accept ctx, build_nxdomain_response(dns_msg, dns_raw, VALIDATOR_REASON), "response_validator_block", txid_hex

  -- ── Override : sinkhole (reproduction 0.0.0.0/:: + EDE Filtered) ─
  if override and override.kind == "sinkhole"
    write_block_event ctx
    sink = { a: override.a or {}, aaaa: override.aaaa or {}, ttl: override.ttl }
    return patch_and_accept ctx, build_sinkhole_response(dns_msg, dns_raw, VALIDATOR_REASON, sink), "response_validator_sinkhole", txid_hex

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
            inject_answers ctx, inject_opts, redirect_answers
          if level_enabled "DEBUG"
            log_debug -> { action: "response_validator_redirect", target: override.cname_target, src_ip: src_ip, dst_ip: dst_ip, txid: txid_hex, client_mac: client_mac, user: user }
          return settle ctx, NF_ACCEPT, patched, (#redirect_answers > 0)
      return settle ctx, NF_DROP, nil, false
    -- même CNAME → on continue vers le chemin normal (passthrough)

  -- ── Chemin normal (pass) : callbacks on_response + injection nft ──
  response_hooks = (entry and entry.response_rule_ids and #entry.response_rule_ids > 0) and entry.response_rule_ids or nft_rule_id
  resp_ctx = run_on_response response_hooks, dns_raw, reason, { resolver_ip: resolver_ip }

  dns_raw = resp_ctx.dns_raw
  payload_modified = resp_ctx.modified
  inject_nft = resp_ctx.inject_nft

  -- ── Strip dynamique : qname terminal de chaîne CNAME déjà appris ──────
  -- Uniquement si cette réponse n'est PAS elle-même celle qui amorce la chaîne
  -- (resp_ctx.chain_strip_rr nil), sinon double-strip inutile.
  if chain_strip_enabled and not resp_ctx.chain_strip_rr
    qname0 = dns_msg.questions[1] and dns_msg.questions[1].name
    new_raw, dyn_mod = maybe_dynamic_strip qname0, dns_raw, mac_ipc.strip_target
    if dyn_mod
      dns_raw          = new_raw
      payload_modified = true
      resp_ctx.action_label or= "response_chain_strip"

  answers_dns = dns_msg
  -- Re-parse UNIQUEMENT si le payload a été réécrit (callback on_response :
  -- strip/CNAME — toujours `ctx.modified = true`, cf. filter/actions — ou strip
  -- dynamique ci-dessus). Sinon `dns_raw` est exactement celui déjà parsé en
  -- tête de `handle_response` (`parse_dns_packet` rend le même `dns_msg`) :
  -- reparser ne produirait qu'une copie jetable de la même table (cf.
  -- docs/agents/perf.md §18).
  if payload_modified
    parsed_modified, _ = parse_dns dns_raw, 1, false
    answers_dns = parsed_modified if parsed_modified

  -- ── Apprentissage : si cette réponse vient d'être strippée pour une règle
  -- follow_cname (resp_ctx.chain_strip_rr posé par dns_strip), enregistre les
  -- cibles CNAME de la chaîne pour que le strip s'applique aussi à la
  -- question TERMINALE séparée que peut émettre un résolveur chasseur.
  if chain_strip_enabled and strip_learn_wfd and resp_ctx.chain_strip_rr
    record_chain_targets answers_dns, dns_raw, resp_ctx.chain_strip_rr,
      (m) -> libc.write strip_learn_wfd, m, #m

  answers = {}
  for a in *parse_answers answers_dns
    if a.rtype == QTYPE.A or a.rtype == QTYPE.AAAA
      fam = a.rtype == QTYPE.AAAA and "ipv6" or "ipv4"
      answers[#answers + 1] = { family: fam, addr: a.rdata_str, ttl: a.ttl }

  -- Sondes de portail captif : une réponse `dnsonly` autorise la résolution
  -- sans injecter l'IP dans les sets d'accès (skip_nft), mais sa destination
  -- est mémorisée par MAC dans `captive_probe_mac4/6`. Une règle nft placée
  -- AVANT le dispatch y redirige le SYN/80 : l'IP d'une sonde peut être
  -- partagée avec un CDN autorisé par une autre règle (mesuré le 2026-11-12 :
  -- addons.mozilla.org et firefox-portal-detection.com partagent
  -- 151.101.x.91 / 2a04:4e42::/48), donc le match par IP seule laisse passer la
  -- sonde vers le vrai serveur (204 → Firefox NOT_CAPTIVE, pas de bandeau).
  probe_recs = 0
  if dnsonly and mac_valid client_mac
    for ans in *answers
      add = ans.family == "ipv4" and add_mac4 or add_mac6
      probe_recs += 1 if add client_mac, ans.addr, CAPTIVE_PROBE_SET, rr_timeout(ans.ttl), ack_corr

  -- Même raison que dans inject_answers : pas de purge pendant un lot NFQUEUE.
  drain_ack! if inject_nft and not dnsonly and not ctx.defer

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
  if level_enabled "DEBUG"
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
      if level_enabled "DEBUG"
        log_debug -> { action: "nft_add_failed_policy_fail_closed", txid: txid_hex, client_ip: client_ip, qnames: qnames, user: user }
      return settle ctx, NF_DROP, nil, false
    else
      log_warn -> { action: "nft_add_failed_fail_open", txid: txid_hex, client_ip: client_ip, qnames: qnames, user: user }

  settle ctx, NF_ACCEPT, (payload_modified and patched or nil), (records_to_add > 0 or probe_recs > 0)

-- ── Bus de verdicts inter-workers ────────────────────────────────────
-- Avec plusieurs workers réponses (`nfqueue.responses` = plage), la réponse
-- d'origine (A : client ↔ résolveur) et celle du validateur (B : client ↔
-- validateur) portent des couples d'adresses différents. Le hachage de flux du
-- noyau (hash_v4 trie saddr/daddr, sans les ports) les envoie donc à des files
-- différentes : le verdict calculé par le worker qui reçoit B doit être
-- diffusé aux autres, sinon A expirerait systématiquement en fail-open.
-- `finalize_a` est remplaçable en test (aucun paquet NFQUEUE forgé).
_finalize_impl = nil

--- Décharge une réponse A parquée avec le verdict désormais connu.
-- @tparam table ctx      Contexte paquet parqué (muté : defer)
-- @tparam table override Verdict validateur (cf. make_override)
-- @treturn nil
release_parked = (ctx, override) ->
  if _finalize_impl
    _finalize_impl ctx, override
  else
    finalize_a ctx, override
  nil

--- Diffuse un verdict B à tous les workers réponses (best-effort).
-- Sans bus (un seul worker) : no-op strict. L'écriture est atomique
-- (ligne < PIPE_BUF) ; un pipe plein (worker bloqué) perd le verdict, et la
-- réponse A concernée expirera en fail-open — comportement historique.
-- @tparam string client_ip IP du client (dst de B)
-- @tparam number txid      ID de transaction DNS
-- @tparam string qname     Nom de la question
-- @tparam table  override  Verdict issu de make_override
-- @treturn nil
broadcast_verdict = (client_ip, txid, qname, override) ->
  return unless so_bus_wfds and #so_bus_wfds > 0
  line = second_opinion.encode_verdict client_ip, txid, qname, override
  return unless line
  for fd in *so_bus_wfds
    libc.write fd, line, #line
  nil

--- Applique une ligne du bus de verdicts.
-- Si la réponse A est parquée dans CE worker, elle est déchargée immédiatement ;
-- sinon le verdict est mémorisé pour une A qui arrivera plus tard (même clé de
-- corrélation : client, txid, qname).
-- @tparam string  line  Ligne encodée (second_opinion.encode_verdict)
-- @tparam boolean defer true en fin de lot NFQUEUE (verdict groupé avec l'ACK)
-- @treturn boolean true si une réponse A parquée a été déchargée
apply_verdict_record = (line, defer) ->
  return false unless so_state
  rec, err = second_opinion.decode_verdict line
  unless rec
    log_warn -> { action: "so_verdict_bus_invalid", reason: err or "decode_failed" }
    return false
  key = so_state.corr_key rec.client_ip, rec.txid, rec.qname
  ctx = so_state.take_parked key
  if ctx
    ctx.defer = defer
    release_parked ctx, rec.override
    true
  else
    so_state.store_verdict key, rec.override, now!
    false

--- Draine le pipe de verdicts de CE worker (non bloquant).
-- @tparam boolean defer true si appelé en fin de lot NFQUEUE (verdicts différés)
-- @treturn number Nombre de réponses A déchargées
drain_verdict_bus = (defer) ->
  return 0 unless so_bus_rfd
  released = 0
  while true
    n = libc.read so_bus_rfd, so_bus_read_buf, SO_BUS_CHUNK
    if n == 0
      -- Tous les écrivains ont fermé (arrêt) : ne pas boucler sur POLLHUP.
      break
    if n < 0
      errno_p = libc.__errno_location!
      errno = if errno_p then errno_p[0] else 0
      break if errno == 11   -- EAGAIN / EWOULDBLOCK (même valeur sous Linux)
      log_warn -> { action: "so_verdict_bus_read_failed", errno: errno }
      break
    so_bus_buf ..= ffi.string so_bus_read_buf, n
    if #so_bus_buf > 8192 and not so_bus_buf\find "\n", 1, true
      log_warn -> { action: "so_verdict_bus_oversize", size: #so_bus_buf }
      so_bus_buf = ""
    while true
      nl = so_bus_buf\find "\n", 1, true
      break unless nl
      line = so_bus_buf\sub 1, nl - 1
      so_bus_buf = so_bus_buf\sub nl + 1
      continue if #line == 0
      released += 1 if apply_verdict_record line, defer
  released

--- Construit les champs de la trace INFO d'une réponse orpheline (fonction pure).
-- C'est le SEUL témoin d'une réponse client jetée faute de question appariée :
-- la trace est donc émise en INFO (visible avec `log_level: "INFO"` en
-- production) et non plus seulement en DEBUG. Le taux d'émission est borné par
-- `log.moon` (RL_CONFIG.response_orphan_dropped : clé = action seule, fenêtre
-- 10 s, état mmap partagé entre workers, occurrences agrégées dans
-- `suppressed=N`), ce qui rend un flood impossible même à 400 réponses
-- orphelines/s.
-- @tparam table info Champs d'enquête : txid, src_ip (résolveur), dst_ip
--                    (client), dst_port, vlan, qname, rcode, client_mac, user,
--                    ipc_retry_attempts, ipc_retry_wait_ms,
--                    retry_budget_skipped
-- @treturn table Champs prêts pour log_info
build_orphan_fields = (info) ->
  {
    action: "response_orphan_dropped"
    src_ip: info.src_ip
    dst_ip: info.dst_ip
    dst_port: info.dst_port
    vlan: info.vlan
    txid: info.txid
    qname: info.qname or "-"
    rcode: info.rcode
    client_mac: info.client_mac
    user: info.user
    ipc_retry_attempts: info.ipc_retry_attempts
    ipc_retry_wait_ms: info.ipc_retry_wait_ms
    retry_budget_skipped: info.retry_budget_skipped and 1 or 0
  }

--- Balaye les réponses A parquées dont le budget est dépassé (fail-open).
sweep_parked = ->
  -- Verdicts B reçus d'un autre worker (multi-worker) : les appliquer AVANT de
  -- faire expirer les parqués, sinon on relâcherait en fail-open une réponse
  -- dont le verdict est déjà arrivé.
  drain_verdict_bus false
  return unless so_state and so_state.has_parked!
  for ctx in *so_state.expired current_benchmark_ms!
    -- Hors lot NFQUEUE (appelé depuis on_idle) : poser le verdict immédiatement.
    ctx.defer = false
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
  -- Âge noyau de la réponse (nil si le noyau n'horodate pas) : sert uniquement
  -- à sauter un retry d'appariement sans espoir. Une réponse n'est JAMAIS
  -- délestée sur l'âge : si une entrée pending existe, elle est servable.
  response_age_ms = if IPC_RETRY_ENABLED then packet_age_ms nfad else nil

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
  -- parse_dns_packet gère IPv4 et IPv6, UDP et TCP, et le header DNS en un seul appel.
  ip, l4, dns_msg, dns_raw, ip_ihl = parse_dns_packet raw, tcp_state
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
    purge_pending os.time
    purge_strip_query_cache ts
    so_state.purge_verdicts ts if so_state

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
        -- Plusieurs workers réponses : la réponse A correspondante peut être
        -- parquée dans un AUTRE processus (couples d'adresses différents →
        -- files différentes, cf. drain_verdict_bus). On diffuse le verdict.
        broadcast_verdict client_ip, txid, q1.name, override
        parked_ctx = so_state.take_parked key
        if parked_ctx
          finalize_a parked_ctx, override
        else
          so_state.store_verdict key, override, ts
      return NF_DROP

  -- ── Vérification IPC ─────────────────────────────────────────
  entry = get_pending_entry txid, dst_ip, client_port, resolver_ip, now
  -- Retry d'appariement IPC (réponse arrivée avant la lecture de la question) :
  -- distinct du retry upstream (`entry.upstream_retries`).
  ipc_retry_attempts = 0
  ipc_retry_wait_ms = 0
  retry_budget_skipped = false
  unless entry
    -- Réponse plus vieille que pending_ttl : le token IPC de la question a été
    -- écrit avant que celle-ci ne parte en amont, donc il a déjà été drainé (ou
    -- l'entrée a expiré). Les sommeils du retry ne peuvent plus apparier ;
    -- sauter ce coût garde l'appariement des vieilles orphelines bon marché.
    if retry_worthwhile response_age_ms, pending_ttl
      entry, ipc_retry_attempts, ipc_retry_wait_ms, retry_budget_skipped = retry_pending_match txid, dst_ip, client_port, resolver_ip, ts
    if entry
      log_info -> {
        action: "response_matched_after_retry"
        src_ip: src_ip
        dst_ip: dst_ip
        txid: txid_hex
        ipc_retry_attempts: ipc_retry_attempts
        ipc_retry_wait_ms: ipc_retry_wait_ms
        user: user
      }
    else
      -- Non-appariement définitif : la réponse est JETÉE (choix défensif : ne
      -- jamais relayer une réponse non sollicitée). Événement grave (une
      -- réponse client perdue) qui n'était visible qu'en DEBUG, donc jamais en
      -- production (`log_level: "INFO"`) : il est désormais émis en INFO,
      -- rate-limité par `log.moon` (RL_CONFIG.response_orphan_dropped : clé =
      -- action seule, fenêtre 10 s, état partagé entre workers via la table
      -- mmap → au plus une ligne par 10 s et occurrences reportées dans
      -- `suppressed=`). Volumétrie : à 400 réponses orphelines/s, 1 ligne/10 s
      -- au lieu de 400 lignes/s. Le LOG DEBUG ci-dessous est conservé pour le
      -- détail et gardé par `level_enabled "DEBUG"` au call-site : sans cette
      -- garde, la closure serait allouée par paquet même quand le niveau est
      -- filtré.
      q1 = dns_msg.questions and dns_msg.questions[1]
      log_info -> build_orphan_fields {
        src_ip: src_ip
        dst_ip: dst_ip
        dst_port: client_port
        vlan: l2.vlan
        txid: txid_hex
        qname: q1 and q1.name or "-"
        rcode: dns_msg.header.rcode
        client_mac: client_mac
        user: user
        ipc_retry_attempts: ipc_retry_attempts
        ipc_retry_wait_ms: ipc_retry_wait_ms
        retry_budget_skipped: retry_budget_skipped
      }
      if level_enabled "DEBUG"
        log_debug -> {
          action:    if ipc_retry_attempts > 0 then "response_no_matching_question_after_retry" else "response_no_matching_question"
          src_ip:    src_ip
          dst_ip:    dst_ip
          vlan:      l2.vlan
          txid:      txid_hex
          rcode:     dns_msg.header.rcode
          client_mac: client_mac
          ipc_retry_attempts: ipc_retry_attempts
          ipc_retry_wait_ms: ipc_retry_wait_ms
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
    if level_enabled "DEBUG"
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
  -- `action=dns_benchmark` (préfixé `response_`) est exempté de rate-limiting
  -- (règle `dns_benchmark` de `RL_NEVER_LIMIT`) : sur un banc à qname fixe, la
  -- règle ALLOW/BLOCK (30 s, empreinte mac_src/qname/qtype) ne garderait qu'un
  -- échantillon par triplet et perdrait les mesures des autres — l'objet même
  -- de l'option. Le worker question supprime sa propre ligne ALLOW/BLOCK quand
  -- benchmark est actif.
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
        ipc_retry_wait_ms:  ipc_retry_wait_ms
        ipc_retry_attempts: ipc_retry_attempts
      }
      -- Mesures µs parallèles (non additives). `ack_wait_us` porte l'attente
      -- du dernier wait_ack TERMINÉ sur ce worker (typiquement la transaction
      -- précédente : l'ACK de la transaction courante n'a pas encore eu lieu).
      -- `log_write_us` porte la durée du dernier write de journal terminé
      -- (souvent la ligne benchmark précédente). Voir doc/CONFIG.md.
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
        ack_wait_us:       take_last_ack_wait_us!
        log_write_us:      get_last_write_us!
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
    if level_enabled "DEBUG"
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
  q1 = dns_msg.questions and dns_msg.questions[1]
  ctx = {
    :qh_ptr, :pkt_id, :raw, :ip, :l4, :ip_ihl, :dns_msg, :dns_raw, :entry
    :resolver_ip, :dnsonly, :nft_rule_id, :ack_corr
    :client_ip, :client_mac, :user, :txid
    vlan: l2.vlan, :src_ip, :dst_ip
    qname: q1 and q1.name and q1.name\lower! or "-"
    af:    ip.version == 6 and "ipv6" or "ipv4"
    -- Verdict différé à la fin du lot NFQUEUE (un seul ACK nft par lot) :
    -- cf. settle / flush_deferred et docs/agents/perf.md.
    defer: true
  }

  -- Second avis : corrélation avec la réponse validateur (B) uniquement si la
  -- règle porte l'action `validate`.
  --   • verdict déjà connu  → appliquer immédiatement (block/redirect/pass) ;
  --   • verdict pas encore là → parquer A (verdict NFQUEUE différé) jusqu'à B
  --     ou expiration du budget (fail-open, balayé par sweep_parked).
  do_so = entry and entry.modifiers and entry.modifiers.validate
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
    -- Purge les ACK résiduels d'un producteur précédent et remet le compteur
    -- d'acquittement à zéro (sinon un vieux seq élevé satisferait une attente).
    nft_q.reset_ack_state! if rfd.ack_rfd and rfd.worker_idx != nil
    events_wfd = rfd.events_wfd
    chain_strip_enabled = rfd.chain_strip_enabled or false
    strip_learn_wfd     = rfd.strip_learn_wfd
    -- Bus de verdicts validateur (multi-worker) : nil à un seul worker.
    so_bus_rfd  = rfd.so_rfd
    so_bus_wfds = rfd.so_wfds
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

  -- Flush des verdicts différés après chaque lecture netlink : indispensable au
  -- chemin nominal (le lot est vidé même sans second avis).
  -- Avec un bus inter-workers, on draine d'abord les verdicts B reçus : une
  -- réponse A parquée qui vient d'être débloquée est ajoutée au lot courant et
  -- donc acquittée avec lui (un seul ACK nft par lot, y compris ses insertions).
  -- `read_packets` (argument fourni par nfq_loop) est utilisé par flush_deferred
  -- pendant l'attente d'ACK pour continuer à vider la file noyau : les paquets
  -- lus forment le lot suivant, acquitté séparément (cf. _flush_batch).
  on_batch = (read_packets) ->
    drain_verdict_bus true if so_bus_rfd
    flush_deferred read_packets
  run_opts = { on_batch_end: on_batch }
  -- Réveil immédiat sur verdict reçu (multi-worker) : sans cela, une réponse A
  -- parquée attendrait le timeout de poll (budget second avis, 80 ms) alors que
  -- son verdict est déjà là. Sans bus : comportement inchangé.
  --
  -- Le tube question→réponse de CE worker est TOUJOURS surveillé par le même
  -- poll : sans lui, il n'était drainé que dans `handle_response`, donc
  -- seulement à l'arrivée d'un paquet sur SA file. Or le hachage NFQUEUE
  -- répartit par couple d'adresses : une file peut rester inactive assez
  -- longtemps pour que les 64 Kio du tube se remplissent → le worker questions
  -- échouait en EAGAIN, jetait chaque question (NF_DROP) et plus aucune réponse
  -- n'arrivait : blocage définitif (cf. docs/agents/perf.md §12).
  extra_rfds = { pipe_rfd }
  extra_rfds[#extra_rfds + 1] = so_bus_rfd if so_bus_rfd
  run_opts.extra_rfds = extra_rfds
  run_opts.on_extra_ready = ->
    -- Même lecture que `handle_response` (aucune duplication) : `drain_pipe` +
    -- le callback `drain_on_msg` qui alimente mac_clients.
    drain_ts = now!
    drain_pipe pipe_rfd, now, drain_on_msg
    -- Ce chemin peut être le SEUL à tourner sur un worker dont la file ne
    -- reçoit aucun paquet : la purge de `handle_response` (compteur mod 1000)
    -- ne s'exécuterait jamais et les entrées absorbées ne partiraient qu'à
    -- l'éviction `ipc.pending_max`. Purge bornée (coût O(pending)) tous les
    -- DRAIN_PURGE_EVERY réveils.
    drain_purge_counter = (drain_purge_counter + 1) % DRAIN_PURGE_EVERY
    purge_pending now if drain_purge_counter == 0
    drain_verdict_bus false if so_bus_rfd
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
      run_opts.idle_ms = so_cfg.budget_ms or 80
      run_opts.on_idle = sweep_parked
      log_info -> { action: "dns_validator_responses_armed", resolvers: table.concat(all_resolvers, ","), ipv4: families.ipv4, ipv6: families.ipv6 }

  run_queue tonumber(queue_num), handle_response, run_opts

--- Injecte le fd de lecture du pipe IPC (tests unitaires uniquement ; en
-- production c'est `run` qui le positionne après le fork).
-- @tparam number|nil fd  Descripteur de lecture du pipe question→réponse
-- @treturn nil
_set_pipe_rfd = (fd) ->
  pipe_rfd = fd
  nil

--- Injecte l'état « second avis » (tests unitaires uniquement).
-- @tparam table|nil st État second_opinion.new, ou nil
-- @treturn nil
_set_so_state = (st) ->
  so_state = st
  nil

--- Injecte les fd du bus de verdicts (tests unitaires uniquement).
-- @tparam number|nil rfd  fd de lecture de ce worker
-- @tparam table|nil wfds  fds d'écriture (fan-out vers tous les workers)
-- @treturn nil
_set_so_bus = (rfd, wfds) ->
  so_bus_rfd  = rfd
  so_bus_wfds = wfds
  so_bus_buf  = ""
  nil

--- Remplace `finalize_a` dans le déchargement des parqués (tests uniquement).
-- @tparam function|nil fn Espion (ctx, override), ou nil pour restaurer
-- @treturn nil
_set_finalize_impl = (fn) ->
  _finalize_impl = fn
  nil

{ :run, :rr_timeout, :patch_modified_dns, :bench_delta, :build_benchmark_fields,
  :skip_ipv6_ext_hdrs, :new_dns_tcp_stream,
  :try_upstream_retry, :arm_retry_fds, :format_block_event,
  :record_chain_targets, :maybe_dynamic_strip, :purge_strip_query_cache,
  :update_mac_clients, :purge_mac_clients, :ip_to_mac,
  :current_benchmark_us, :take_last_ack_wait_us,
  :plan_retry_tries, :retry_pending_match, :retry_worthwhile, :_retry_budget, :_set_pipe_rfd,
  :build_orphan_fields,
  :settle, :flush_deferred, :deferred_count, :_set_defer_deps, :_reset_deferred,
  :finalize_a, :broadcast_verdict, :drain_verdict_bus, :apply_verdict_record,
  :release_parked, :_set_so_state, :_set_so_bus, :_set_finalize_impl }
