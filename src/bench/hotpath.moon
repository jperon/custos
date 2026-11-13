--
-- SPDX-FileCopyrightText: (c) 2026 jperon <cataclop@hotmail.com>
-- SPDX-License-Identifier: MIT OR GPL-2.0-only
--

--- Micro-banc de profilage CPU du hot path DNS (question / réponse / second avis).
-- Rejoue en boucle, SANS NFQUEUE ni réseau, les handlers RÉELS des workers
-- (`handle_question`, `handle_response`) sur des paquets IPv4/UDP fabriqués,
-- avec des stubs minimaux :
--   * `libnfq` : `nfq_get_payload` rend un paquet pré-construit,
--     `nfq_set_verdict*` compte, `nfq_get_packet_hw` rend une MAC fixe ;
--   * `nft_queue` : réel, mais son tube est vidé après chaque lot (le worker
--     `nft` n'existe pas) et `ack_rfd` reste nil → `wait_ack` rend sans attendre
--     (l'attente d'ACK n'est pas du CPU, cf. docs/agents/perf.md §3.1) ;
--   * `IPC` : réel. Les transactions `pending` sont réinjectées par le banc
--     (`ipc.set_pending`) — le coût complet du tube (écriture + lecture +
--     décodage) est mesuré à part par le cas `ipc_drain` ;
--   * `raw_send` : stub sans socket (aucun paquet n'est émis, aucun accès réseau).
--
-- Règles du filtre réelles (`filter.load`) : les règles par défaut de
-- `config.moon` (captives, SafeSearch, canari DoH) suivies des règles du banc
-- (`r_utilisateurs` avec action `validate` → second avis, `r_ouverture_complete`,
-- `r_refus_ariori`), et transaction IPC réelle : la sonde de mise en place
-- rejoue une question par domaine pour récupérer `pending` EXACTEMENT telle que
-- `worker_questions` l'écrit (rule_id, raison, modifiers, response_rule_ids).
--
-- Usage (cf. src/bench/README.md et docs/agents/perf.md §18) :
--   make bench-hotpath
--   make bench-hotpath HP_PROFILE=f HP_DURATION=12
--   make bench-hotpath HP_EXTRA="--only so_cycle --iters 200000"
--
-- Sorties : `tmp/prof/hotpath.md` (+ synthèse sur stdout).

ffi = require "ffi"
gc_tune = require "lib.gc_tune"
stage_probe = require "bench.stage_probe"
{ :s2ip } = require "ipparse.l3.ip"
sp = require("ipparse.lib.pack_compat").pack

libc = ffi.C

-- ── Constantes du banc ────────────────────────────────────────────────

PROF_DIR       = "tmp/prof"
SESSIONS_PATH  = PROF_DIR .. "/sessions.lua"
OUT_PATH       = PROF_DIR .. "/hotpath.md"

CLIENT_IP      = "10.35.1.2"
CLIENT_PORT    = 5353
RESOLVER_IP    = "10.35.1.1"
VALIDATOR_IP   = "10.35.4.1"
CLIENT_MAC     = "d8:d3:85:63:6b:27"
CLIENT_USER    = "j@prn.ovh"
CLIENT_MAC_RAW = string.char(0xd8, 0xd3, 0x85, 0x63, 0x6b, 0x27)

QNAME_TLS = "controlplane.login.tailscale.com"
QNAME_VPN = "vpn.stemarie.dynv6.net"
TXID      = 0x1234

-- 8 enregistrements A : profil « authentifié + second avis » de perf.md §16.3.
ADDRS_TLS = {
  "100.64.0.11", "100.64.0.12", "100.64.0.13", "100.64.0.14"
  "100.64.0.15", "100.64.0.16", "100.64.0.17", "100.64.0.18"
}
ADDRS_VPN = { "185.199.108.153" }
ADDRS_B   = { "167.235.236.107" }
-- Réponse du validateur (B) du profil « mixed » : le validateur rend les mêmes
-- 8 A que le résolveur (§21/§23 : le profil authentifié a 8 A).
ADDRS_VAL = ADDRS_TLS

O_NONBLOCK     = 2048
F_SETPIPE_SZ   = 1031
NFT_PIPE_BYTES = 1048576   -- 64 réponses × ~1,3 Ko de lignes nft par lot

NF_ACCEPT = 1
NF_DROP   = 0

-- ── État du banc (mutables, capturés par les closures) ────────────────

payload_buf = ffi.new "uint8_t[65536]"
payload_ptr = ffi.cast "unsigned char*", payload_buf
payload_len = 0

-- En-tête L2 factice (type cdef'able seulement après require "ffi_defs" :
-- alloué dans install_stubs). `hw_hdr` est conservé au niveau module : un
-- pointeur FFI ne maintient pas vivante sa cible pendant le GC.
hw_hdr = nil
hw_ptr = nil

-- Compteurs de validation (stub libnfq) : un paquet = un verdict attendu.
verdicts       = 0
dup_sent       = 0
run_queue_calls = {}

-- ── Règles du filtre du banc ──────────────────────────────────────────
-- Profil authentifié : `r_utilisateurs` (allow + validate → duplication vers le
-- validateur, 8 A), `r_ouverture_complete` (allow simple, 1 A), puis le refus
-- par défaut. Les règles par défaut de config.moon (captives, SafeSearch,
-- canari DoH) restent en tête de `config.filter.rules` (celles-ci sont ajoutées
-- à la fin).
BENCH_RULES = {
  {
    rule_id:      "r_utilisateurs"
    description:  "Utilisateurs"
    actions:      { "allow", { validate: {} } }
    conditions:   {
      to_domains: { QNAME_TLS, "login.tailscale.com", "dns.tailscale.com", "tailscale.com" }
    }
  }
  {
    rule_id:      "r_ouverture_complete"
    description:  "Ouverture complète"
    actions:      { "allow" }
    conditions:   {
      to_domains: { QNAME_VPN, "dynv6.net" }
    }
  }
  {
    rule_id:      "r_refus_a_priori"
    description:  "Refus a priori"
    actions:      { "deny" }
  }
}

ALL_CASES = { "question", "ipc_drain", "response", "so_a", "so_cycle",
  "mixed_o2", "mixed_plain", "setup_control" }

-- ── Fabrication de paquets (pur, testé par tests/unit/bench/hotpath_spec) ──

--- Encode un nom DNS en labels (`www.example.com` → labels + nul).
-- @tparam string name Nom de domaine.
-- @treturn string Encodage wire.
encode_name = (name) ->
  parts = {}
  for label in (name\gmatch "[^%.]+")
    parts[#parts + 1] = string.char(#label) .. label
  table.concat(parts) .. "\0"

--- Construit un message DNS requête (qr=0, RD).
-- @tparam string qname  Nom demandé.
-- @tparam number txid   Identifiant de transaction.
-- @treturn string Payload DNS wire.
build_query = (qname, txid=TXID) ->
  header = sp(">H H H H H H", txid, 0x0100, 1, 0, 0, 0)
  header .. encode_name(qname) .. sp(">H H", 1, 1)

--- Construit un message DNS réponse (qr=1) avec N enregistrements A.
-- @tparam string qname    Nom demandé.
-- @tparam number txid     Identifiant de transaction.
-- @tparam table  addrs    Liste d'adresses IPv4 (chaînes "a.b.c.d").
-- @tparam table|nil opts  { ttl, flags } — défaut 60 / 0x8180.
-- @treturn string Payload DNS wire.
build_answer = (qname, txid, addrs, opts=nil) ->
  opts = opts or {}
  ttl   = opts.ttl or 60
  flags = opts.flags or 0x8180
  header = sp(">H H H H H H", txid, flags, 1, #addrs, 0, 0)
  qsection = encode_name(qname) .. sp(">H H", 1, 1)
  parts = {}
  for ip in *addrs
    parts[#parts + 1] = "\192\012" .. sp(">H H I4 H", 1, 1, ttl, 4) .. s2ip(ip)
  header .. qsection .. table.concat(parts)

--- Enveloppe un payload DNS dans un paquet IPv4/UDP.
-- @tparam string src    IP source.
-- @tparam string dst    IP destination.
-- @tparam number sport   Port source.
-- @tparam number dport   Port destination.
-- @tparam string dns     Payload DNS.
-- @treturn string Paquet IP brut.
ipv4_udp = (src, dst, sport, dport, dns) ->
  udp_len = 8 + #dns
  total   = 20 + udp_len
  hdr = sp(">B B H H H B B H", 0x45, 0, total, 0x2222, 0, 64, 17, 0)
  hdr .. s2ip(src) .. s2ip(dst) .. sp(">H H H H", sport, dport, udp_len, 0) .. dns

--- Paquet question client → résolveur.
-- @tparam string qname Nom demandé.
-- @treturn string Paquet IP brut.
build_question_packet = (qname) ->
  ipv4_udp CLIENT_IP, RESOLVER_IP, CLIENT_PORT, 53, build_query(qname)

--- Paquet réponse résolveur/validateur → client.
-- @tparam string src    IP du serveur (résolveur ou validateur).
-- @tparam string qname  Nom demandé.
-- @tparam table  addrs  Adresses A de la réponse.
-- @tparam table|nil opts Options (ttl, flags) de build_answer.
-- @treturn string Paquet IP brut.
build_response_packet = (src, qname, addrs, opts=nil) ->
  ipv4_udp src, CLIENT_IP, 53, CLIENT_PORT, build_answer(qname, TXID, addrs, opts)

-- ── Utilitaires de mesure ─────────────────────────────────────────────

--- Les `n` plus grosses entrées d'une table {clé → compte}, décroissantes.
-- @tparam table counts Comptes.
-- @tparam number n     Nombre maximal d'entrées.
-- @treturn table Liste de { key, count }.
top_n = (counts, n) ->
  list = {}
  for k, v in pairs counts
    list[#list + 1] = { key: k, count: v }
  table.sort list, (a, b) -> a.count > b.count
  out = {}
  for i = 1, math.min(n, #list)
    out[#out + 1] = list[i]
  out

--- Pourcentage formaté (une décimale).
-- @tparam number part  Part.
-- @tparam number total Total.
-- @treturn string "12.3"
format_pct = (part, total) ->
  if total > 0 then string.format("%.1f", 100 * part / total) else "0.0"

--- Concatène une table de lignes dans un fichier.
-- @tparam string path  Chemin cible (répertoire déjà créé).
-- @tparam table  lines Lignes (sans \n final).
-- @treturn boolean true si écrit.
write_file = (path, lines) ->
  fh = io.open path, "w"
  return false unless fh
  fh\write table.concat(lines, "\n")
  fh\write "\n"
  fh\close!
  true

-- ── Stubs ─────────────────────────────────────────────────────────────

--- Installe les stubs AVANT le chargement des workers.
-- `ffi_defs` réel est chargé d'abord (cdef + bibliothèques) puis remplacé par
-- une table de même forme dont `libnfq` délègue au réel sauf les six
-- fonctions appelées par le banc. `raw_send` est remplacé (aucun socket, aucun
-- paquet émis) et `nfq_loop.run_queue` est neutralisé (les workers appellent
-- `run` mais ne bouclent pas).
-- @treturn nil
install_stubs = ->
  real = require "ffi_defs"

  -- Métadonnées L2 : MAC du client, ifindex bridge, aucune nfmark (pas de VLAN).
  hw_hdr = ffi.new "nfqnl_msg_packet_hw[1]"
  ffi.copy hw_hdr[0].hw_addr, CLIENT_MAC_RAW, 6
  hw_hdr[0].hw_addrlen = 6
  hw_ptr = ffi.cast "nfqnl_msg_packet_hw*", hw_hdr

  overrides = {
    nfq_get_payload: (nfad, out) ->
      out[0] = payload_ptr
      payload_len
    nfq_set_verdict: (qh, id, verdict, datalen, buf) ->
      verdicts += 1
      0
    nfq_set_verdict2: (qh, id, verdict, mark, datalen, buf) ->
      verdicts += 1
      0
    nfq_get_packet_hw: (nfad) -> hw_ptr
    nfq_get_indev: (nfad) -> 5
    nfq_get_nfmark: (nfad) -> 0
  }
  package.loaded["ffi_defs"] = {
    ffi: real.ffi
    libc: real.libc
    libnfq: setmetatable(overrides, { __index: real.libnfq })
    libnft: real.libnft
    libwolfssl: real.libwolfssl
  }

  package.loaded["raw_send"] = {
    open: (version) -> 42
    routable: (version, dst) -> true
    send: (fd, version, pkt, dst) ->
      dup_sent += 1
      true
    IPPROTO_RAW: 255
    IPPROTO_UDP: 17
  }

  nfq_loop = require "nfq_loop"
  nfq_loop.run_queue = (queue_num, callback, opts) ->
    run_queue_calls[#run_queue_calls + 1] = { :queue_num, :callback, :opts }
    nil
  nil

--- Installe les sondes par étape (option `--stages`).
-- À appeler APRÈS `filter.load` mais AVANT le `require` des workers : les
-- workers capturent leurs dépendances par destructuration au chargement
-- (`{ :f } = require "m"`), donc un wrapper posé plus tard ne serait pas vu.
-- Les sondes sont inclusives (une fonction appelée en interne par son module
-- via une variable locale n'est pas interceptable) : cf. bench/stage_probe.moon.
-- @tparam table p Jeu de sondes (bench.stage_probe.new).
-- @treturn nil
install_probes = (p) ->
  p.wrap require("packet_utils"), "parse_dns_packet", "parse_dns_packet"
  p.wrap require("ipc"), "drain_pipe", "ipc.drain_pipe"
  p.wrap require("ipc"), "get_pending_entry", "ipc.get_pending_entry"
  p.wrap require("ipc"), "consume", "ipc.consume"
  p.wrap require("ipc"), "write_msg", "ipc.write_msg"
  p.wrap require("lib.dns_response"), "parse_answers", "parse_answers"
  p.wrap require("lib.dns_response"), "replace_dns_payload", "replace_dns_payload"
  p.wrap require("dns_ede"), "patch_modified_dns", "patch_modified_dns"
  p.wrap require("dns_ede"), "strip_https_rr", "strip_https_rr"
  p.wrap require("dns_classify"), "classify", "dns_classify.classify"
  p.wrap require("second_opinion"), "encode_verdict", "encode_verdict"
  p.wrap_state require("second_opinion"), "new",
    { "corr_key", "take_verdict", "store_verdict", "take_parked", "park", "is_validator" }
  p.wrap require("response_inject"), "inject", "response_inject.inject"
  p.wrap require("nft_queue"), "add_ip4", "nft.add_ip4"
  p.wrap require("nft_queue"), "add_mac4", "nft.add_mac4"
  p.wrap require("auth.sessions"), "user_for_mac", "user_for_mac"
  p.wrap require("lib.packet_parsing"), "ip2s", "ip2s"
  p.wrap require("dup_query"), "get_picker", "dup.get_picker"
  p.wrap require("dup_query"), "build_udp", "dup.build_udp"
  p.wrap require("filter"), "decide_meta", "filter.decide_meta"
  p.wrap require("filter"), "run_on_response", "filter.run_on_response"
  p.wrap require("log"), "log_allow", "log.log_allow"
  p.wrap require("log"), "log_info", "log.log_info"
  nil

--- Charge la configuration du banc (AVANT tout require de worker).
-- @treturn table module config.
apply_config = ->
  config = require "config"
  config.runtime or= {}
  config.runtime.log_level = "INFO"
  config.runtime.benchmark = false
  -- Répertoire d'exécution des workers → dans le projet (jamais /var/run) :
  -- worker_questions y écrit son instantané metrics au démarrage.
  config.runtime.pid_file = PROF_DIR .. "/custos.pid"
  config.metrics or= {}
  config.second_opinion or= {}
  config.second_opinion.resolvers = { VALIDATOR_IP }
  config.auth or= {}
  config.auth.sessions_file = SESSIONS_PATH
  config.auth.redirect_url = nil
  config.dns or= {}
  config.dns.upstream_retry = {
    enabled: true, max_attempts: 2, rcodes: { 2, 3, 5 }
    nxdomain_bad_ttl: 60, nxdomain_bad_max: 4096
  }
  config.ipc or= {}
  config.ipc.pending_ttl = 5
  config.ipc.match_retry = { count: 5, sleep_ms: 20, budget_ms: 100 }
  config.nft or= {}
  config.nft.family  = "bridge"
  config.nft.family6 = "bridge"
  -- Table INEXISTANTE : `filter.load` appelle `ip_whitelist.init`, qui exécute
  -- `flush set <family> <table> ip*_dest_whitelist`. Sur une machine où custos
  -- tourne, garder la vraie table viderait les sets du ruleset vivant : avec
  -- une table absente, le flush échoue sans effet (cf. docs/agents/perf.md §18.1).
  config.nft.table   = "hotpath_bench_no_table"
  config.nft.ip_timeout = "2m"
  config.filter or= {}
  config.filter.allow_localnets = false
  -- Les règles du banc sont AJOUTÉES aux règles déjà normalisées (défauts).
  unless config.__hotpath_rules
    for r in *BENCH_RULES
      config.filter.rules[#config.filter.rules + 1] = r
    config.__hotpath_rules = true
  config

--- Écrit le fichier de sessions du client (dans ./tmp/ uniquement).
-- @treturn boolean true si écrit.
write_sessions_file = ->
  sessions = {}
  sessions[CLIENT_MAC] = {
    user: CLIENT_USER
    expires: os.time! + 86400
    mac: CLIENT_MAC
    ips: { ipv4: CLIENT_IP }
  }
  auth_sessions = require "auth.sessions"
  auth_sessions.write_sessions sessions, SESSIONS_PATH

--- Tube non bloquant, optionnellement agrandi (F_SETPIPE_SZ).
-- @tparam number|nil size Taille demandée en octets.
-- @treturn number fd lecture
-- @treturn number fd écriture
make_pipe = (size=nil) ->
  fds = ffi.new "int[2]"
  rc = libc.pipe2 fds, O_NONBLOCK
  error "pipe2() échoué" if rc != 0
  if size
    libc.fcntl fds[1], F_SETPIPE_SZ, size
  tonumber(fds[0]), tonumber(fds[1])

--- Vide un fd non bloquant (aucune allocation par appel).
-- @tparam number fd Descripteur.
-- @treturn nil
drain_fd = (fd) ->
  return nil unless fd and fd >= 0
  buf = ffi.new "uint8_t[?]", 4096
  while true
    n = libc.read fd, buf, 4096
    break unless n and n > 0
  nil

--- Lit UNE ligne complète du pipe (la sonde en écrit une seule).
-- @tparam number fd fd de lecture.
-- @treturn string|nil Ligne (sans \n) ou nil.
read_line = (fd) ->
  buf = ffi.new "uint8_t[?]", 4096
  n = libc.read fd, buf, 4096
  return nil unless n and n > 0
  (ffi.string buf, tonumber(n))\match "^[^\n]*"

-- ── Mise en place ─────────────────────────────────────────────────────

--- Construit l'environnement complet du banc (workers réels, stubs, paquets).
-- @tparam table opts Options CLI (voir parse_args).
-- @treturn table Environnement partagé par les cas de mesure.
setup = (opts={}) ->
  os.execute "mkdir -p #{PROF_DIR}"
  config = apply_config!
  install_stubs!

  -- Réglage GC du banc : surcharge éventuelle par les options CLI puis
  -- application (setpause/setstepmul) via le module de production. Les
  -- mesures « tas max » de run_case comparent donc les configurations.
  config.gc = config.gc or {}
  for key in *{"pause", "stepmul", "idle_step", "max_heap_mb"}
    override = opts["gc_" .. key]
    config.gc[key] = override if override != nil
  gc_state = gc_tune.new config.gc
  gc_state.apply!

  write_sessions_file!

  -- Filtre réel (règles de config + règles du banc).
  filter = require "filter"
  filter.load!

  -- Sondes par étape (--stages) : installées avant le require des workers,
  -- qui capturent leurs dépendances au chargement.
  probes = nil
  if opts.stages
    probes = stage_probe.new!
    install_probes probes

  -- Tubes (mêmes rôles que main.moon).
  qpipe_r, qpipe_w = make_pipe!
  learn_r, learn_w = make_pipe!
  ev_r, ev_w       = make_pipe!
  nft_r, nft_w     = make_pipe NFT_PIPE_BYTES
  sobus_r, sobus_w = make_pipe!

  -- Workers réels : `run` installe les callbacks, `nfq_loop.run_queue` stubbé
  -- les capture sans boucler.
  wq = require "worker_questions"
  wq.run 0, qpipe_w, learn_w, ev_w, nil

  ipc = require "ipc"
  resp = require "worker_responses"
  -- Le worker réponses lit le MÊME tube que celui où le worker questions écrit
  -- (qpipe_r) : c'est ce que fait la production (main.moon passe le fd de
  -- lecture du tube question→réponse). Les cas `response`/`so_*` injectent leur
  -- transaction par `ipc.set_pending` et laissent donc le tube vide.
  resp.run(4, {
    question_response_rfd: qpipe_r
    events_wfd: ev_w
    nft_wfd: nft_w
    chain_strip_enabled: false
  }, filter.get_rules!.rules_metadata)

  -- Bus de verdicts du second avis : la production multi-worker écrit un verdict
  -- B encodé dans un tube par worker (`broadcast_verdict`). Sans bus, ce coût
  -- (encodage + écriture) serait nul dans le banc, seul l'écrivain est donc armé
  -- ici (réception câblée à nil : pas de rebouclage) et le tube est vidé par lot
  -- comme celui de nft_queue. Mesure donc l'encodage + UNE écriture ; sur la
  -- cible à deux workers réponses, il y en a une par worker.
  resp._set_so_bus nil, { sobus_w }

  -- Le client est connu du worker réponses (dans la production, c'est le drain
  -- du tube qui l'apprend) : on le pré-remplit comme le fait `run()`.
  resp.update_mac_clients { mac_str: CLIENT_MAC, ipv4: true, ip_str: CLIENT_IP }, os.time!

  set_payload = (pkt) ->
    ffi.copy payload_buf, pkt, #pkt
    payload_len = #pkt
    nil

  -- Paquets de référence.
  pkt_question     = build_question_packet QNAME_TLS
  pkt_question_vpn = build_question_packet QNAME_VPN
  pkt_resp_a       = build_response_packet RESOLVER_IP, QNAME_TLS, ADDRS_TLS
  pkt_resp_b       = build_response_packet VALIDATOR_IP, QNAME_TLS, ADDRS_B
  pkt_resp_b8      = build_response_packet VALIDATOR_IP, QNAME_TLS, ADDRS_VAL
  pkt_resp_vpn     = build_response_packet RESOLVER_IP, QNAME_VPN, ADDRS_VPN

  -- Sonde : une question réelle par domaine, pour récupérer la transaction IPC
  -- EXACTEMENT telle que worker_questions l'écrit (rule_id, raison, modifiers,
  -- response_rule_ids, timeout).
  probe = (pkt) ->
    set_payload pkt
    wq.handle_question nil, nil, 1
    line = read_line qpipe_r
    decoded = nil
    if line
      msg, err = ipc.decode_msg line
      error "décodage IPC de la sonde impossible : #{err}" unless msg
      decoded = msg
    drain_fd learn_r
    drain_fd ev_r
    drain_fd qpipe_r
    decoded

  msg_tls = probe pkt_question
  msg_vpn = probe pkt_question_vpn
  error "sonde IPC vide (question TLS)" unless msg_tls
  error "sonde IPC vide (question VPN)" unless msg_vpn

  -- Ligne IPC pré-encodée pour le cas ipc_drain.
  ipc_line = ipc.encode_msg(
    msg_tls.txid, s2ip(CLIENT_IP), msg_tls.src_port, CLIENT_MAC_RAW,
    s2ip(RESOLVER_IP), false, msg_tls.reason, nil,
    msg_tls.rule_id, msg_tls.timeout, msg_tls.modifiers,
    msg_tls.response_rule_ids, nil
  )
  error "encode_msg a échoué" unless ipc_line

  set_payload pkt_question

  -- ── Préparation des micro-cas ──────────────────────────────────────
  -- Paquets RÉELS parsés une fois (le micro-cas ne mesure que l'appel) et
  -- objets dérivés. `micro_*` n'est jamais utilisé par les cas de cycle.
  packet_utils = require "packet_utils"
  micro_tcp = packet_utils.new_dns_tcp_stream!
  micro_p = {}
  for key, pkt in pairs { q: pkt_question, a: pkt_resp_a, b: pkt_resp_b8 }
    ip, l4, msg, raw, ihl = packet_utils.parse_dns_packet pkt, micro_tcp
    error "parse du paquet micro #{key} impossible" unless msg
    micro_p[key] = { :ip, :l4, :msg, :raw, :ihl }
  -- Verdict B du profil (pass) et sélecteur de validateur réels.
  second_opinion = require "second_opinion"
  dns_classify = require "dns_classify"
  micro_so = second_opinion.new { resolvers: { VALIDATOR_IP }, budget_ms: 80 }
  micro_vi = dns_classify.classify micro_p.b.msg, micro_p.b.raw
  micro_override = { kind: "pass" }
  -- Requête de décision du filtre (mêmes champs que worker_questions).
  micro_req = {
    domain: QNAME_TLS, src_ip: CLIENT_IP, mac: CLIENT_MAC
    vlan: nil, ts: os.time!, user: CLIENT_USER
  }
  -- Champs d'une ligne events (mêmes clés que worker_questions.write_event).
  micro_fields = {
    qname: QNAME_TLS, mac_src: CLIENT_MAC, src_ip: CLIENT_IP, dst_ip: RESOLVER_IP
    vlan: nil, user: CLIENT_USER, af: "ipv4", reason: "Allowed by rule: Utilisateurs"
    rule: "r_utilisateurs"
  }
  -- Entrée pending dédiée (txid distinct : ne perturbe pas les cas réponse).
  micro_msg = {}
  micro_msg[k] = v for k, v in pairs msg_tls
  micro_msg.txid = 0x7777
  ipc.set_pending micro_msg, os.time
  -- Tubes dédiés aux micro-cas (jamais lus par les workers).
  micro_pipe_r, micro_pipe_w = make_pipe!

  {
    :config, :filter, :wq, :resp
    :qpipe_r, :qpipe_w, :learn_r, :ev_r, :ev_w, :nft_r, :nft_w
    :sobus_r, :sobus_w
    :micro_pipe_r, :micro_pipe_w
    :micro_p, :micro_tcp, :micro_so, :micro_vi, :micro_override, :micro_req
    :micro_fields, :micro_msg
    :set_payload
    :pkt_question, :pkt_question_vpn, :pkt_resp_a, :pkt_resp_b
    :pkt_resp_b8, :pkt_resp_vpn
    :msg_tls, :msg_vpn, :ipc_line, :probes
    :gc_state
    on_idle_q: run_queue_calls[1].opts and run_queue_calls[1].opts.on_idle
    on_idle_r: run_queue_calls[2].opts and run_queue_calls[2].opts.on_idle
    -- Fin de lot du worker questions : c'est là que la production vide les
    -- tampons events/learn (cf. docs/agents/perf.md §20). nil quand la version
    -- mesurée n'a pas de tampon (comparaison avant/après).
    on_batch_end_q: run_queue_calls[1].opts and run_queue_calls[1].opts.on_batch_end
    on_batch_end_r: run_queue_calls[2].opts and run_queue_calls[2].opts.on_batch_end
    handle_question: run_queue_calls[1].callback
    handle_response: run_queue_calls[2].callback
  }

-- ── Cas de mesure ─────────────────────────────────────────────────────

  --- Noms des cas « micro » (fonctions réelles mesurées isolément).
-- Chaque micro-cas appelle UNE fonction du hot path avec des arguments réels
-- (paquets et objets préparés par `setup`) et rend un nombre : la valeur de
-- retour est consommée, ce qui empêche le JIT d'éliminer l'appel (§22.1).
-- Les micro-cas sont hors des cas par défaut : `HP_EXTRA=--micro`, ou
-- `--only micro_<nom>` pour un seul.
MICRO_CASES = {
  "micro_parse_q", "micro_parse_a", "micro_parse_b",
  "micro_decide", "micro_write_msg", "micro_encode_msg",
  "micro_build_udp", "micro_decode", "micro_makekey",
  "micro_add_line", "micro_add_group", "micro_parse_answers", "micro_strip",
  "micro_classify", "micro_encode_verdict", "micro_corr_key",
  "micro_ip2s", "micro_write_event", "micro_learn", "micro_user",
  "micro_get_pending", "micro_is_valid_timeout"
}

--- Construit les micro-cas : une fonction réelle, arguments préparés par setup.
-- Le `finish` éventuel fait le vidage que la production fait en fin de lot
-- (tampons events/learn, flush nft) ; il est chronométré par run_case.
-- @tparam table s Environnement de setup.
-- @treturn table Liste de cas.
build_micro_cases = (s) ->
  ipc = require "ipc"
  packet_utils = require "packet_utils"
  dns_ede = require "dns_ede"
  disp = require "lib.dns_response"
  nft_q = require "nft_queue"
  second_opinion = require "second_opinion"
  dns_classify = require "dns_classify"
  dup = require "dup_query"
  { :user_for_mac } = require "auth.sessions"
  { :add_ip4, :add_ip4_many } = require "nft_queue"
  { :write_msg } = require "ipc"
  { :ip2s } = require "lib.packet_parsing"
  ipc_hex = require "lib.ipc_hex"

  drain_micro = ->
    drain_fd s.micro_pipe_r
    drain_fd s.nft_r
    drain_fd s.learn_r
    drain_fd s.ev_r
    drain_fd s.sobus_r

  -- Un cas = un appel mesuré ; la valeur rendue est un nombre (consommé).
  micro = (name, desc, fn, opts=nil) ->
    opts or= {}
    {
      name: name
      desc: desc
      pkts: 1
      labels: { name }
      steps: { (i) -> fn i }
      finish: opts.finish
      drain: opts.drain or drain_micro
    }

  q, a, b = s.micro_p.q, s.micro_p.a, s.micro_p.b
  now_fn = require("log").now

  add_line_step = (i) ->
    (add_ip4 CLIENT_IP, "100.64.0.11", "r_utilisateurs", "660s",
      "1234:10.35.1.2:5353:10.35.1.1") and 1 or 2
  -- Les 8 adresses d'une réponse mixed (response_inject.inject groupe par set).
  add_group_addrs = [ "100.64.0.#{10 + i}" for i = 1, 8 ]
  add_group_step = (i) ->
    add_ip4_many CLIENT_IP, add_group_addrs, "r_utilisateurs", "660s",
      "1234:10.35.1.2:5353:10.35.1.1"
  wevent_step = (i) -> (s.wq.write_event s.micro_fields, true) and 1 or 2
  learn_step  = (i) -> (s.wq.write_learn_msg q.ip.src, CLIENT_MAC_RAW) and 1 or 2

  {
    micro "micro_parse_q", "parse_dns_packet (question client 78 o)", ->
      ip, l4, msg = packet_utils.parse_dns_packet s.pkt_question, s.micro_tcp
      (msg and 1) or 2
    micro "micro_parse_a", "parse_dns_packet (réponse A, 8 RR)", ->
      ip, l4, msg = packet_utils.parse_dns_packet s.pkt_resp_a, s.micro_tcp
      (msg and 1) or 2
    micro "micro_parse_b", "parse_dns_packet (réponse validateur B, 8 RR)", ->
      ip, l4, msg = packet_utils.parse_dns_packet s.pkt_resp_b8, s.micro_tcp
      (msg and 1) or 2
    micro "micro_decide", "filter.decide_meta (règle à second avis)", ->
      (s.filter.decide_meta s.micro_req) and 1 or 2
    micro "micro_write_msg", "ipc.write_msg : encodage 14 champs + write", ->
      (write_msg s.micro_pipe_w, s.msg_tls.txid, q.ip.src, s.msg_tls.src_port,
        CLIENT_MAC_RAW, q.ip.dst, s.msg_tls.reason, nil, s.msg_tls.rule_id,
        s.msg_tls.timeout, s.msg_tls.modifiers, s.msg_tls.response_rule_ids, nil) and 1 or 2
    micro "micro_encode_msg", "ipc.encode_msg seul (aucune écriture)", ->
      #(ipc.encode_msg s.msg_tls.txid, q.ip.src, s.msg_tls.src_port, CLIENT_MAC_RAW,
        q.ip.dst, false, s.msg_tls.reason, nil, s.msg_tls.rule_id, s.msg_tls.timeout,
        s.msg_tls.modifiers, s.msg_tls.response_rule_ids, nil)
    micro "micro_build_udp", "dup_query.build_udp (duplication validateur)", ->
      #(dup.build_udp q.ip, q.l4, q.raw, VALIDATOR_IP, s.pkt_question)
    micro "micro_decode", "ipc.decode_msg (14 champs)", ->
      (ipc.decode_msg s.ipc_line) and 1 or 2
    micro "micro_makekey", "ipc.make_key (clé pending)", ->
      #(ipc.make_key TXID, CLIENT_IP, CLIENT_PORT, RESOLVER_IP)
    micro "micro_add_line", "nft_queue.add_ip4 : build_line + enqueue", add_line_step,
      { finish: -> nft_q.get_last_seq! }
    micro "micro_add_group", "nft_queue.add_ip4_many (8 adresses, 1 ligne)", add_group_step,
      { finish: -> nft_q.get_last_seq! }
    micro "micro_parse_answers", "lib.dns_response.parse_answers (8 RR)", ->
      #(disp.parse_answers a.msg)
    micro "micro_strip", "dns_ede.patch_modified_dns (strip HTTPS + EDE)", ->
      new_dns, mod = dns_ede.patch_modified_dns a.raw, "Allowed by rule: Utilisateurs"
      #new_dns + (mod and 1 or 0)
    micro "micro_classify", "dns_classify.classify (réponse validateur)", ->
      v = dns_classify.classify b.msg, b.raw
      (v and v.verdict == "pass") and 1 or 2
    micro "micro_encode_verdict", "second_opinion.encode_verdict (bus verdicts)", ->
      #(second_opinion.encode_verdict CLIENT_IP, TXID, QNAME_TLS, s.micro_override)
    micro "micro_corr_key", "second_opinion.corr_key (clé second avis)", ->
      #(s.micro_so.corr_key CLIENT_IP, TXID, QNAME_TLS)
    micro "micro_ip2s", "ip2s (4 octets → texte)", ->
      #(ip2s q.ip.src)
    micro "micro_write_event", "worker_questions.write_event (ligne TSV tamponnée)", wevent_step,
      { finish: -> s.wq.flush_pipes! }
    micro "micro_learn", "worker_questions.write_learn_msg (22 o tamponnés)", learn_step,
      { finish: -> s.wq.flush_pipes! }
    micro "micro_user", "auth.sessions.user_for_mac (session du client)", ->
      (user_for_mac CLIENT_MAC, CLIENT_IP, s.config.auth.sessions_file) and 1 or 2
    micro "micro_get_pending", "ipc.get_pending_entry (hit)", ->
      (ipc.get_pending_entry 0x7777, CLIENT_IP, CLIENT_PORT, RESOLVER_IP, now_fn) and 1 or 2
    micro "micro_is_valid_timeout", "ipc_hex.is_valid_timeout (1×/ligne nft)", ->
      (ipc_hex.is_valid_timeout "660s") and 1 or 2
  }

--- Construit les cas de mesure (préparation + étapes par paquet, par lots).
-- @tparam table s Environnement de setup.
-- @treturn table Liste de cas { name, desc, pkts, pre, steps, finish, drain }.
build_cases = (s) ->
  ipc = require "ipc"
  log_mod = require "log"
  now_fn = log_mod.now
  msg_tls = s.msg_tls
  msg_vpn = s.msg_vpn

  drain_all = ->
    drain_fd s.qpipe_r
    drain_fd s.learn_r
    drain_fd s.ev_r
    drain_fd s.nft_r
    drain_fd s.sobus_r

  drain_cb = (msg) ->
    s.resp.update_mac_clients msg, now_fn!

  consume_tls = ->
    ipc.consume TXID, CLIENT_IP, CLIENT_PORT, RESOLVER_IP
    1

  {
    {
      name: "question"
      desc: "handle_question : parse, décision filtre, ALLOW, IPC, événement, apprentissage, duplication"
      pkts: 1
      pre: (i) ->
        s.on_idle_q! if s.on_idle_q
        s.set_payload s.pkt_question
      steps: { (i) -> s.handle_question nil, nil, i }
      -- Fin de lot NFQUEUE : vidage des tampons events/learn comme en production
      -- (no-op pour une version sans tampon, ce qui rend l'avant/après comparable).
      finish: -> s.on_batch_end_q! if s.on_batch_end_q
      drain: drain_all
    }
    {
      name: "ipc_drain"
      desc: "tube question→réponse : écriture + lecture + décodage + insertion pending (1 message)"
      pkts: 1
      steps: {
        (i) ->
          libc.write s.qpipe_w, s.ipc_line, #s.ipc_line
          ipc.drain_pipe s.qpipe_r, now_fn, drain_cb
          ipc.consume TXID, CLIENT_IP, CLIENT_PORT, RESOLVER_IP
          NF_ACCEPT
      }
      drain: drain_all
    }
    {
      name: "response"
      desc: "handle_response sans second avis (r_ouverture_complete, 1 A, injection nft)"
      pkts: 1
      pre: (i) ->
        s.on_idle_r! if s.on_idle_r
        s.set_payload s.pkt_resp_vpn
        ipc.set_pending msg_vpn, now_fn
      steps: { (i) -> s.handle_response nil, nil, i }
      finish: -> s.resp.flush_deferred!
      drain: drain_all
    }
    {
      name: "so_a"
      desc: "réponse A avec validate → parquage (sans déchargement)"
      pkts: 1
      pre: (i) ->
        s.on_idle_r! if s.on_idle_r
        s.set_payload s.pkt_resp_a
        ipc.set_pending msg_tls, now_fn
      steps: { (i) -> s.handle_response nil, nil, i }
      finish: -> s.resp.flush_deferred!
      drain: drain_all
    }
    {
      name: "so_cycle"
      desc: "cycle second avis complet : réponse A parquée + réponse B validateur (8 A, 16 insertions nft)"
      pkts: 2
      pre: (i) ->
        s.on_idle_r! if s.on_idle_r
        s.set_payload s.pkt_resp_a
        ipc.set_pending msg_tls, now_fn
      steps: {
        (i) -> s.handle_response nil, nil, i          -- A : parquage
        (i) ->
          s.set_payload s.pkt_resp_b
          s.handle_response nil, nil, i              -- B : déchargement + finalize
      }
      finish: -> s.resp.flush_deferred!
      drain: drain_all
    }
    {
      name: "mixed_o2"
      desc: "cycle mixed complet AVEC second avis : question → A parquée → B validateur (classify, broadcast, déparquage, finalize 8 A)"
      pkts: 1   -- une requête CLIENT (1 question + 2 réponses) : µs/paquet = µs/requête
      labels: { "q_handler", "q_flush", "r_a_park", "r_b_verdict", "r_flush" }
      pre: (i) ->
        s.on_idle_q! if s.on_idle_q
        s.set_payload s.pkt_question
      steps: {
        (i) -> s.handle_question nil, nil, i
        (i) -> s.on_batch_end_q! if s.on_batch_end_q
        (i) ->
          s.set_payload s.pkt_resp_a
          s.handle_response nil, nil, i
        (i) ->
          s.set_payload s.pkt_resp_b8
          s.handle_response nil, nil, i
        (i) ->
          s.resp.flush_deferred!
          nil
      }
      drain: drain_all
    }
    {
      name: "mixed_plain"
      desc: "cycle mixed SANS second avis : question + réponse A du résolveur (1 A, injection nft)"
      pkts: 1   -- une requête client
      labels: { "q_handler", "q_flush", "r_a_finalize", "r_flush" }
      pre: (i) ->
        s.on_idle_q! if s.on_idle_q
        s.set_payload s.pkt_question_vpn
      steps: {
        (i) -> s.handle_question nil, nil, i
        (i) -> s.on_batch_end_q! if s.on_batch_end_q
        (i) ->
          s.set_payload s.pkt_resp_vpn
          s.handle_response nil, nil, i
        (i) ->
          s.resp.flush_deferred!
          nil
      }
      drain: drain_all
    }
    {
      name: "setup_control"
      desc: "préparation seule des cas réponse (set_pending + consume) : incluse dans leurs mesures"
      pkts: 1
      pre: (i) ->
        ipc.set_pending msg_tls, now_fn
      steps: { (i) -> consume_tls! }
      drain: drain_all
    }
  }

-- ── Exécution ────────────────────────────────────────────────────────

--- Exécute `iters` itérations d'un cas par lots de `chunk` (≈ MAX_BATCH_PKTS).
-- La préparation et les étapes sont chronométrées ensemble ; le flush de fin de
-- lot (`finish`) l'est aussi (dans la production, il a lieu une fois par lot) ;
-- le vidage des tubes (`drain`) ne l'est pas (c'est le travail du worker nft et
-- du superviseur).
-- @tparam table  c     Cas.
-- @tparam number iters Nombre d'itérations.
-- @tparam number chunk Taille de lot.
-- @treturn number Temps CPU cumulé (secondes, os.clock).
-- @treturn table Compteurs de codes retour {code → n}.
-- @treturn number Nombre de verdicts posés pendant l'intervalle.
-- @treturn number Durée du lot le plus rapide (secondes) : la machine partage
--         ses cœurs avec d'autres processus, le minimum par lot est la seule
--         mesure stable d'un coût par paquet (le total, lui, est bruyant).
-- @treturn number Tas maximum observé (Kio, collectgarbage "count" après lot).
run_case = (c, iters, chunk) ->
  rets = {}
  v0 = verdicts
  total = 0
  min_block = nil
  heap_max = collectgarbage "count"
  blocks = math.ceil iters / chunk
  for b = 1, blocks
    n = math.min chunk, iters - (b - 1) * chunk
    t0 = os.clock!
    for i = 1, n
      c.pre i if c.pre
      for step in *c.steps
        r = step i
        rets[r] = (rets[r] or 0) + 1 if r != nil
    c.finish! if c.finish
    t1 = os.clock!
    dt = t1 - t0
    total += dt
    if n == chunk and (min_block == nil or dt < min_block)
      min_block = dt
    c.drain! if c.drain
    heap = collectgarbage "count"
    heap_max = heap if heap > heap_max
  total, rets, verdicts - v0, min_block, heap_max

--- Mesure l'allocation brute (octets/paquet) avec le GC arrêté.
-- @tparam table  c     Cas.
-- @tparam number iters Nombre d'itérations.
-- @treturn number Octets alloués par paquet.
measure_alloc = (c, iters) ->
  collectgarbage "collect"
  collectgarbage "stop"
  before = collectgarbage "count"
  blocks = math.ceil iters / 64
  for b = 1, blocks
    n = math.min 64, iters - (b - 1) * 64
    for i = 1, n
      c.pre i if c.pre
      for step in *c.steps
        step i
    c.finish! if c.finish
    c.drain! if c.drain
  after = collectgarbage "count"
  collectgarbage "restart"
  collectgarbage "collect"
  math.max(0, after - before) * 1024 / iters

-- ── Mesure par étape ──────────────────────────────────────────────────

--- Noms des étapes d'un cas (labels explicites ou « stepN »).
-- @tparam table c Cas.
-- @treturn table Liste de noms.
step_names = (c) ->
  out = {}
  for i = 1, #c.steps
    out[i] = (c.labels and c.labels[i]) or "step#{i}"
  out

--- Mesure le temps CPU de CHAQUE étape d'un cas (µs par itération).
-- L'horloge est lue autour de chaque appel d'étape : son coût (~20 ns) est
-- négligeable devant les étapes mesurées, et il est identique avant/après une
-- optimisation. La préparation (`pre`), le `finish` et le `drain` ne sont pas
-- chronométrés ici (le `finish` l'est par run_case). Comme run_case, on garde
-- le MINIMUM de `reps` passages par étape : la machine est partagée.
-- @tparam table  c     Cas.
-- @tparam number iters Nombre d'itérations.
-- @tparam number chunk Taille de lot.
-- @tparam number reps  Nombre de passages (minimum retenu).
-- @treturn table Liste { name, us } dans l'ordre des étapes.
measure_steps = (c, iters, chunk, reps) ->
  names = step_names c
  best = {}
  for rep = 1, math.max(1, reps)
    acc = {}
    for i = 1, #names
      acc[i] = 0
    blocks = math.ceil iters / chunk
    for b = 1, blocks
      n = math.min chunk, iters - (b - 1) * chunk
      for i = 1, n
        c.pre i if c.pre
        for si, step in ipairs c.steps
          t0 = os.clock!
          step i
          acc[si] += os.clock! - t0
      c.finish! if c.finish
      c.drain! if c.drain
    for si = 1, #names
      if best[si] == nil or acc[si] < best[si]
        best[si] = acc[si]
  out = {}
  for si = 1, #names
    out[#out + 1] = { name: names[si], us: best[si] * 1e6 / iters }
  out

--- Mesure l'allocation de CHAQUE étape d'un cas, GC arrêté (octets par itération).
-- Le relevé de tas (`collectgarbage "count"`, en Kio) encadre chaque appel
-- d'étape. GC arrêté : aucune collecte ne fausse le relevé (cf.
-- docs/agents/perf.md §22.1).
-- PIÈGE MESURÉ : LuaJIT interne les chaînes identiques, donc une étape qui
-- reconstruit la MÊME chaîne à chaque itération n'alloue qu'une fois et
-- apparaîtrait à ~0 o/itération. On échauffe donc UN lot (chaînes constantes
-- internées) puis on mesure UN lot : c'est la steady-state. Corollaire : les
-- chaînes constantes (ligne IPC d'un même txid, ligne events d'un même qname)
-- sont sous-estimées, les valeurs uniques par itération (seq nft, txid variable
-- en production) sont exactes.
-- @tparam table  c     Cas.
-- @tparam number iters Nombre d'itérations (garder petit : cf. ci-dessus).
-- @tparam number chunk Taille de lot.
-- @treturn table Liste { name, bytes } dans l'ordre des étapes.
measure_steps_alloc = (c, iters, chunk) ->
  names = step_names c
  acc = {}
  for i = 1, #names
    acc[i] = 0
  -- Échauffement (un lot : interning des constantes) hors mesure.
  for i = 1, chunk
    c.pre i if c.pre
    for step in *c.steps
      step i
  c.finish! if c.finish
  c.drain! if c.drain
  collectgarbage "collect"
  collectgarbage "stop"
  blocks = math.ceil iters / chunk
  for b = 1, blocks
    n = math.min chunk, iters - (b - 1) * chunk
    for i = 1, n
      c.pre i if c.pre
      for si, step in ipairs c.steps
        c0 = collectgarbage "count"
        step i
        acc[si] += (collectgarbage "count") - c0
    c.finish! if c.finish
    c.drain! if c.drain
  collectgarbage "restart"
  collectgarbage "collect"
  out = {}
  for si = 1, #names
    out[#out + 1] = { name: names[si], bytes: math.max(0, acc[si]) * 1024 / iters }
  out

--- Exécute un cas avec les sondes par étape actives et rend leurs résultats.
-- Les sondes étant installées AVANT le chargement des workers, elles couvrent
-- tout le processus : lancer un passage séparé (option --stages).
-- @tparam table  c     Cas.
-- @tparam number iters Nombre d'itérations.
-- @tparam number chunk Taille de lot.
-- @tparam table  p     Jeu de sondes.
-- @treturn table Résultats triés (cf. bench.stage_probe.results).
run_probed = (c, iters, chunk, p) ->
  p.reset!
  blocks = math.ceil iters / chunk
  for b = 1, blocks
    n = math.min chunk, iters - (b - 1) * chunk
    for i = 1, n
      c.pre i if c.pre
      for step in *c.steps
        step i
    c.finish! if c.finish
    c.drain! if c.drain
  p.results iters

-- ── Profilage jit.profile ─────────────────────────────────────────────

--- Profille un cas avec jit.profile (mode "f" ou "l") pendant `duration` s.
-- Agrège les échantillons par fonction/ligne du haut de pile (et par pile à
-- deux niveaux), plus la distribution des états VM (N/I/C/G/J).
-- @tparam table  c        Cas.
-- @tparam string mode     "f" (fonction) ou "l" (ligne).
-- @tparam number duration Durée minimale en secondes (≥10 conseillé).
-- @tparam number chunk    Taille de lot.
-- @treturn table { flat, stacks, vms, seconds, blocks }.
profile_case = (c, mode, duration, chunk) ->
  profile = require "jit.profile"
  flat = {}
  stacks = {}
  vms = {}
  fmt = if mode == "l" then "l;" else "f;"
  cb = (th, samples, vmst) ->
    vms[vmst] = (vms[vmst] or 0) + samples
    ok, dumped = pcall profile.dumpstack, th, fmt, 2
    if ok and dumped and dumped != ""
      top = dumped\match "^[^;]+"
      flat[top] = (flat[top] or 0) + samples
      stacks[dumped] = (stacks[dumped] or 0) + samples
    nil
  profile.start mode, cb
  wall0 = os.time!
  blocks = 0
  while os.time! - wall0 < duration
    for i = 1, chunk
      c.pre i if c.pre
      for step in *c.steps
        step i
    c.finish! if c.finish
    c.drain! if c.drain
    blocks += 1
  profile.stop!
  { :flat, :stacks, :vms, blocks, seconds: os.time! - wall0 }

-- ── CLI ───────────────────────────────────────────────────────────────

--- Parse les arguments du banc.
-- @tparam table argv Arguments (sans nom de programme).
-- @treturn table Options normalisées.
parse_args = (argv) ->
  o = {
    iters: 100000
    chunk: 64
    warmup: 5000
    duration: 10
    repeat: 3
    profile: nil
    only: nil
    list: false
    jit_v: nil
    jit_dump: nil
    jit_dump_mode: "t"
    gc_pause: nil
    gc_stepmul: nil
    gc_idle_step: nil
    gc_max_heap_mb: nil
    stages: false
    no_steps: false
    micro: false
  }
  i = 1
  next_val = ->
    i += 1
    argv[i]
  while i <= #argv
    switch argv[i]
      when "--iters" then o.iters = tonumber next_val!
      when "--chunk" then o.chunk = tonumber next_val!
      when "--warmup" then o.warmup = tonumber next_val!
      when "--duration" then o.duration = tonumber next_val!
      when "--repeat" then o.repeat = tonumber next_val!
      when "--profile" then o.profile = next_val!
      when "--only"
        o.only or= {}
        for n in (next_val!)\gmatch "[^,]+"
          o.only[#o.only + 1] = n
      when "--micro" then o.micro = true
      when "--list" then o.list = true
      when "--jit-v" then o.jit_v = next_val!
      when "--jit-dump" then o.jit_dump = next_val!
      when "--jit-dump-mode" then o.jit_dump_mode = next_val!
      when "--gc-pause" then o.gc_pause = tonumber next_val!
      when "--gc-stepmul" then o.gc_stepmul = tonumber next_val!
      when "--gc-idle-step" then o.gc_idle_step = tonumber next_val!
      when "--gc-max-heap" then o.gc_max_heap_mb = tonumber next_val!
      when "--stages" then o.stages = true
      when "--no-steps" then o.no_steps = true
    i += 1
  o

-- ── Rapport ───────────────────────────────────────────────────────────

--- Formate les compteurs de codes retour en table compacte.
-- @tparam table rets {code → n}.
-- @treturn string "0=3 1=61"
render_rets = (rets) ->
  parts = {}
  for k, v in pairs rets
    parts[#parts + 1] = "#{k}=#{v}"
  table.sort parts
  table.concat parts, " "

--- Formate le ratio verdicts/paquets d'un résultat.
-- @tparam table r Résultat.
-- @treturn string
render_verdicts = (r) ->
  if r.verdicts > 0
    string.format "%.2f", r.verdicts / (r.iters * r.pkts)
  else
    "0"

--- Ajoute le tableau des mesures au rapport.
-- @tparam table lines Lignes accumulées.
-- @tparam table results Résultats.
-- @tparam table o Options.
-- @treturn nil
render_results = (lines, results, o) ->
  lines[#lines + 1] = ""
  lines[#lines + 1] = "## Mesures (os.clock, GC actif, lots de #{o.chunk}, minimum de #{o.repeat} passages)"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "| cas | iters | paquets | temps (s) | µs/paquet | µs/paquet (lot min) | µs/cycle | octets/paq (GC arrêté) | tas max (Kio) | retours | verdicts/paq |"
  lines[#lines + 1] = "|---|---|---|---|---|---|---|---|---|---|---|"
  for r in *results
    pkts = r.iters * r.pkts
    cycle = if r.pkts > 1 then string.format("%.1f", r.secs * 1e6 / r.iters) else "—"
    min_us = if r.min_block
      string.format("%.1f", r.min_block * 1e6 / (o.chunk * r.pkts))
    else
      "—"
    lines[#lines + 1] = string.format(
      "| %s | %d | %d | %.3f | %.1f | %s | %s | %.0f | %.0f | `%s` | %s |",
      r.name, r.iters, pkts, r.secs, r.secs * 1e6 / pkts,
      min_us, cycle, r.alloc, r.heap_max or 0, render_rets(r.rets), render_verdicts(r)
    )
  nil

--- Ajoute le profilage jit.profile d'un cas au rapport.
-- @tparam table lines   Lignes accumulées.
-- @tparam string name   Nom du cas.
-- @tparam string mode   "f" ou "l".
-- @tparam table  p      Résultat de profile_case.
-- @treturn nil
render_profile = (lines, name, mode, p) ->
  total = 0
  for _, v in pairs p.vms
    total += v
  col = if mode == "l" then "ligne" else "fonction"
  vm_parts = {}
  for k, v in pairs p.vms
    vm_parts[#vm_parts + 1] = "#{k}=#{v} (#{format_pct(v, total)}%)"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "### #{name} — jit.profile mode `#{mode}` (#{p.seconds} s, #{total} échantillons, #{p.blocks} lots)"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "États VM : " .. table.concat(vm_parts, ", ")
  lines[#lines + 1] = ""
  lines[#lines + 1] = "| % | échantillons | #{col} |"
  lines[#lines + 1] = "|---|---|---|"
  for e in *top_n(p.flat, 15)
    lines[#lines + 1] = string.format("| %s | %d | `%s` |", format_pct(e.count, total), e.count, e.key)
  lines[#lines + 1] = ""
  lines[#lines + 1] = "Piles à deux niveaux (appelé ; appelant) :"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "| % | échantillons | pile |"
  lines[#lines + 1] = "|---|---|---|"
  for e in *top_n(p.stacks, 10)
    lines[#lines + 1] = string.format("| %s | %d | `%s` |", format_pct(e.count, total), e.count, e.key)
  nil

--- Part du second avis dans le profil `mixed` mesuré (§23.5 : r_utilisateurs
-- 16 205 / 23 792 réponses client = 68,1 %). Sert à pondérer les deux cas
-- `mixed_o2` (avec second avis) et `mixed_plain` (sans).
MIX_O2_SHARE = 0.68

--- Ajoute le tableau des étapes (temps + allocation) au rapport.
-- @tparam table lines Lignes accumulées.
-- @tparam table steps { nom_du_cas → { time, alloc } } (cf. main).
-- @treturn nil
render_steps = (lines, steps, o) ->
  return nil unless next steps
  lines[#lines + 1] = ""
  lines[#lines + 1] = "## Coût par étape (µs/requête, minimum de #{math.max 1, o.repeat} passages ; octets/requête GC arrêté)"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "Chaque ligne est une étape du cycle réel du cas ; le total est celui du cycle mesuré sans instrumentation (tableau des mesures ci-dessus)."
  order = {}
  for name in pairs steps
    order[#order + 1] = name
  table.sort order
  for name in *order
    st = steps[name]
    total_us = 0
    for e in *st.time
      total_us += e.us
    lines[#lines + 1] = ""
    lines[#lines + 1] = "### `#{name}` — total étapes #{string.format "%.2f", total_us} µs/requête"
    lines[#lines + 1] = ""
    lines[#lines + 1] = "| étape | µs/requête | % | octets/requête |"
    lines[#lines + 1] = "|---|---|---|---|"
    for i, e in ipairs st.time
      bytes = st.alloc[i] and st.alloc[i].bytes or 0
      lines[#lines + 1] = string.format("| `%s` | %.2f | %s | %.0f |",
        e.name, e.us, format_pct(e.us, total_us), bytes)
  nil

--- Ajoute le tableau des sondes par fonction au rapport (option --stages).
-- Les temps sont INCLUSIFS : une sonde peut en contenir une autre (cf.
-- src/bench/stage_probe.moon).
-- @tparam table lines  Lignes accumulées.
-- @tparam table stages { nom_du_cas → résultats de stage_probe.results }.
-- @treturn nil
render_stages = (lines, stages) ->
  return nil unless stages
  lines[#lines + 1] = ""
  lines[#lines + 1] = "## Sondes par fonction (option --stages, temps INCLUSIFS, cycle instrumenté)"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "Le wrapper ajoute ~0,2-0,4 µs par appel : ces totaux sont gonflés, les parts relatives sont lisibles."
  for name, res in pairs stages
    lines[#lines + 1] = ""
    lines[#lines + 1] = "### `#{name}`"
    lines[#lines + 1] = ""
    lines[#lines + 1] = "| sonde | µs/requête | µs/appel | appels/requête | octets/requête |"
    lines[#lines + 1] = "|---|---|---|---|---|"
    for e in *res
      continue if e.calls == 0
      lines[#lines + 1] = string.format("| `%s` | %.2f | %.3f | %.2f | %.0f |",
        e.label, e.us, e.us_call, e.calls_req, e.bytes)
  nil

-- ── Point d'entrée ───────────────────────────────────────────────────

--- Exécute le banc : mesure(s) puis profilage éventuel, écrit le rapport.
-- @tparam table argv Arguments CLI.
-- @treturn table Résultats agrégés.
main = (argv) ->
  o = parse_args argv
  if o.list
    io.write "cas : #{table.concat ALL_CASES, ", "}\n"
    return nil

  s = setup o
  cases = build_cases s
  for c in *build_micro_cases s
    cases[#cases + 1] = c
  by_name = {}
  for c in *cases
    by_name[c.name] = c

  if o.jit_v
    require("jit.v").on o.jit_v
  if o.jit_dump
    require("jit.dump").on o.jit_dump_mode, o.jit_dump

  names = o.only or (o.micro and MICRO_CASES) or ALL_CASES
  results = {}
  for name in *names
    c = by_name[name]
    unless c
      io.write "cas inconnu : #{name} (voir --list)\n"
      os.exit 1
    -- Échauffement JIT (non chronométré, mêmes lots + drains), puis `repeat`
    -- passages chronométrés : on garde le MINIMUM (la machine partage ses
    -- cœurs avec d'autres processus, la médiane serait contaminée).
    run_case c, o.warmup, o.chunk if o.warmup > 0
    best, best_rets, best_v, best_min = nil, nil, nil, nil
    heap_peak = 0
    for rep = 1, math.max(1, o.repeat)
      secs, rets, v, min_block, heap_max = run_case c, o.iters, o.chunk
      if best == nil or secs < best
        best, best_rets, best_v = secs, rets, v
      if min_block and (best_min == nil or min_block < best_min)
        best_min = min_block
      heap_peak = heap_max if heap_max and heap_max > heap_peak
    alloc = measure_alloc c, math.min(o.iters, 20000)
    results[#results + 1] = {
      name: c.name, pkts: c.pkts, iters: o.iters, repeat: math.max(1, o.repeat)
      secs: best, rets: best_rets, verdicts: best_v, :alloc
      min_block: best_min, heap_max: heap_peak
    }

  profiles = {}
  if o.profile
    for name in *names
      profiles[name] = profile_case by_name[name], o.profile, o.duration, o.chunk

  -- Mesure par étape (temps + allocation) des cas qui déclarent des labels.
  steps = {}
  unless o.no_steps
    for name in *names
      c = by_name[name]
      continue unless c.labels and #c.labels == #c.steps
      run_case c, o.warmup, o.chunk if o.warmup > 0
      steps[name] = {
        time:  measure_steps c, o.iters, o.chunk, math.max(1, o.repeat)
        alloc: measure_steps_alloc c, o.chunk, o.chunk
      }

  -- Sondes par étape (--stages), même cycle instrumenté.
  stages = nil
  if s.probes
    stages = {}
    for name in *{"mixed_o2", "mixed_plain"}
      c = by_name[name]
      stages[name] = run_probed c, o.iters, o.chunk, s.probes if c

  if o.jit_v
    require("jit.v").off!
  if o.jit_dump
    require("jit.dump").off!

  -- Vérifications : un chemin non voulu fausse toutes les mesures.
  failures = {}
  for r in *results
    if r.name == "question" and (r.rets[NF_ACCEPT] or 0) != r.iters
      failures[#failures + 1] = "question : #{r.rets[NF_ACCEPT] or 0} NF_ACCEPT pour #{r.iters} itérations"
    if r.name == "response" and (r.rets[-1] or 0) != r.iters
      failures[#failures + 1] = "response : #{r.rets[-1] or 0} verdicts différés pour #{r.iters} itérations"
    if r.name == "so_a" and (r.rets[-1] or 0) != r.iters
      failures[#failures + 1] = "so_a : #{r.rets[-1] or 0} parquages pour #{r.iters} itérations"
    if r.name == "so_cycle" and r.verdicts != r.iters
      failures[#failures + 1] = "so_cycle : #{r.verdicts} verdicts pour #{r.iters} cycles"
    if r.name == "response" and r.verdicts != r.iters
      failures[#failures + 1] = "response : #{r.verdicts} verdicts pour #{r.iters} paquets"
    -- Cycle mixed : 1 question acceptée, 1 réponse A (verdict différé), et pour
    -- le second avis 1 réponse B (NF_DROP) ; un seul verdict posé par requête.
    if r.name == "mixed_o2"
      unless (r.rets[NF_ACCEPT] or 0) == r.iters and (r.rets[-1] or 0) == r.iters and (r.rets[NF_DROP] or 0) == r.iters
        failures[#failures + 1] = "mixed_o2 : retours #{render_rets r.rets} (attendu 1=#{r.iters} -1=#{r.iters} 0=#{r.iters})"
      if r.verdicts != r.iters
        failures[#failures + 1] = "mixed_o2 : #{r.verdicts} verdicts pour #{r.iters} requêtes"
    if r.name == "mixed_plain"
      unless (r.rets[NF_ACCEPT] or 0) == r.iters and (r.rets[-1] or 0) == r.iters
        failures[#failures + 1] = "mixed_plain : retours #{render_rets r.rets} (attendu 1=#{r.iters} -1=#{r.iters})"
      if r.verdicts != r.iters
        failures[#failures + 1] = "mixed_plain : #{r.verdicts} verdicts pour #{r.iters} requêtes"

  lines = {}
  lines[#lines + 1] = "# Micro-banc hot path — #{os.date "%Y-%m-%dT%H:%M:%S"}"
  lines[#lines + 1] = ""
  lines[#lines + 1] = "- LuaJIT #{jit.version} / #{jit.arch} / #{jit.os}"
  lines[#lines + 1] = "- iters=#{o.iters}, repeat=#{o.repeat} (minimum retenu), chunk=#{o.chunk}, warmup=#{o.warmup}, profilage=#{o.profile or "aucun"} (#{o.duration} s)"
  lines[#lines + 1] = string.format(
    "- GC : pause=%d, stepmul=%d, idle_step=%d, max_heap_mb=%d (surcharges CLI appliquées dans setup)",
    s.gc_state.values.pause, s.gc_state.values.stepmul,
    s.gc_state.values.idle_step, s.gc_state.values.max_heap_mb)
  lines[#lines + 1] = "- paquet question : #{#s.pkt_question} o ; réponse A (8 A) : #{#s.pkt_resp_a} o ; réponse B : #{#s.pkt_resp_b} o"
  lines[#lines + 1] = "- duplication émise (stub raw_send) : #{dup_sent} ; verdicts posés (stub libnfq) : #{verdicts}"
  render_results lines, results, o
  render_steps lines, steps, o
  render_stages lines, stages
  -- Total mixte pondéré (68 % avec second avis, 32 % sans, cf. §23.5).
  o2 = nil
  plain = nil
  for r in *results
    o2 = r.secs * 1e6 / r.iters if r.name == "mixed_o2"
    plain = r.secs * 1e6 / r.iters if r.name == "mixed_plain"
  if o2 and plain
    lines[#lines + 1] = ""
    lines[#lines + 1] = string.format(
      "**Total par requête `mixed` pondéré** (#{MIX_O2_SHARE} × `mixed_o2` + %s × `mixed_plain`) : **%.1f µs** (moyenne des passages ; minimum par lot : voir tableau).",
      1 - MIX_O2_SHARE, MIX_O2_SHARE * o2 + (1 - MIX_O2_SHARE) * plain)
  if next profiles
    lines[#lines + 1] = ""
    lines[#lines + 1] = "## Profilage jit.profile"
    for name in *names
      p = profiles[name]
      render_profile lines, name, o.profile, p if p
  if #failures > 0
    lines[#lines + 1] = ""
    lines[#lines + 1] = "## ÉCHECS DE VÉRIFICATION"
    for f in *failures
      lines[#lines + 1] = "- #{f}"

  write_file OUT_PATH, lines
  text = table.concat(lines, "\n") .. "\n"
  io.write text
  io.write "\n[hotpath] rapport : #{OUT_PATH}\n"
  if #failures > 0
    io.write "[hotpath] ÉCHEC DE VÉRIFICATION (#{#failures})\n"
    os.exit 1
  results

{ :parse_args, :main, :encode_name, :build_query, :build_answer, :ipv4_udp,
  :build_question_packet, :build_response_packet, :top_n, :format_pct,
  :BENCH_RULES, :ALL_CASES, :MICRO_CASES, :build_micro_cases, :step_names,
  :measure_steps, :measure_steps_alloc, :run_probed, :install_probes,
  :MIX_O2_SHARE }
