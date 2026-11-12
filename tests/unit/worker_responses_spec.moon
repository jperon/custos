dns_mod = require "ipparse.l7.dns"
sp = require("ipparse.lib.pack_compat").pack

QTYPE_A = dns_mod.types.A
QTYPE_HTTPS = dns_mod.types.HTTPS
QCLASS_IN = dns_mod.classes.IN
qname_example = "\7example\3com\0"
name_ptr = "\192\012"

pack_rr = (rtype, rdata, ttl=60) ->
  name_ptr .. sp(">H H I4 s2", rtype, QCLASS_IN, ttl, rdata)

make_dns_payload = (with_https=false) ->
  question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
  answer_a = pack_rr QTYPE_A, string.char(1, 2, 3, 4)
  if with_https
    answer_https = pack_rr QTYPE_HTTPS, "\0\1"
    header = sp ">H H H H H H", 0x1234, 0x8180, 1, 2, 0, 0
    return header .. question .. answer_a .. answer_https
  header = sp ">H H H H H H", 0x1234, 0x8180, 1, 1, 0, 0
  header .. question .. answer_a

fresh_worker_responses = ->
  package.loaded["worker_responses"] = nil
  dofile "lua/worker_responses.lua"

describe "worker_responses helpers", ->
  before_each ->
    config = require "config"
    config.dns = {
      ttl_grace: {
        grace: 0
        min: 60
        max: 900
      }
    }

  it "rr_timeout borne TTL + grace", ->
    m = fresh_worker_responses!
    config = require "config"

    config.dns.ttl_grace.grace = 0
    _, ttl_min = m.rr_timeout 0
    assert.equals 60, ttl_min
    assert.equals "60s", (m.rr_timeout 0)

    config.dns.ttl_grace.grace = 120
    _, ttl_mid = m.rr_timeout 60
    assert.equals 180, ttl_mid

    _, ttl_max = m.rr_timeout 5000
    assert.equals 900, ttl_max

  it "bench_delta ignore les jalons absents ou négatifs", ->
    m = fresh_worker_responses!
    assert.equals 7, m.bench_delta 17, 10
    assert.is_nil m.bench_delta nil, 10
    assert.is_nil m.bench_delta 10, nil
    assert.is_nil m.bench_delta 10, 17

  it "patch_modified_dns n'ajoute EDE que si le payload change", ->
    m = fresh_worker_responses!
    clean = make_dns_payload false
    patched_clean, modified_clean = m.patch_modified_dns clean, "policy"
    assert.equals clean, patched_clean
    assert.is_false modified_clean
    assert.is_nil patched_clean\find("Custos vigilat", 1, true)

    modified = make_dns_payload true
    patched_modified, modified_flag = m.patch_modified_dns modified, "policy"
    assert.is_true modified_flag
    assert.is_not_nil patched_modified\find("Custos vigilat%. policy", 1)

  it "patch_modified_dns efface le bit AD quand HTTPS/SVCB sont stripés", ->
    m = fresh_worker_responses!
    bit = require "bit"
    -- Create DNS payload with HTTPS record and AD bit set (0x8520)
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    answer_a = pack_rr QTYPE_A, string.char(1, 2, 3, 4)
    answer_https = pack_rr QTYPE_HTTPS, "\0\1"
    header_with_ad = sp(">H H H H H H", 0x1234, 0x8520, 1, 2, 0, 0)
    raw_with_https_and_ad = header_with_ad .. question .. answer_a .. answer_https

    patched, modified = m.patch_modified_dns raw_with_https_and_ad, "test"
    assert.is_true modified
    
    -- Verify AD bit was cleared (0x8520 & ~0x0020 = 0x8500)
    -- Flags field is at bytes 3-4 (1-indexed)
    flags_after = patched\byte(3) * 256 + patched\byte(4)
    assert.equals 0x8500, flags_after
    
    -- Verify HTTPS record was removed
    parsed = dns_mod.parse patched, 1, false
    assert.equals 1, #parsed.answers
    assert.equals QTYPE_A, parsed.answers[1].rtype

  -- ── build_benchmark_fields (verdict + temps dans une ligne ALLOW/BLOCK) ──────
  describe "build_benchmark_fields", ->
    info = {
      client_mac:  "aa:bb:cc:dd:ee:ff"
      vlan:        8
      client_ip:   "10.35.8.2"
      resolver_ip: "1.1.1.1"
      client_port: 5353
      txid:        0x1f4d
      af:          "ipv4"
      user:        "alice@lan"
      qname:       "example.com"
      qtype:       "A"
      ipc_retry_wait_ms:  3
      ipc_retry_attempts: 1
    }
    deltas = {
      delta_ms: 12, question_proc_ms: 4, response_entry_ms: 5, drain_ms: 0
      payload_ms: 1, parse_ms: 2, match_ms: 0, log_ms: 0
      ack_wait_us: 1234, log_write_us: 42
    }

    it "verdict allow quand entry.refused est faux", ->
      m = fresh_worker_responses!
      entry = { refused: false, reason: "Allowed by rule: X", rule_id: "r_ok", dnsonly: false }
      fields, verdict = m.build_benchmark_fields entry, info, deltas
      assert.equals "allow", verdict
      assert.equals "dns_benchmark", fields.action
      assert.equals "r_ok", fields.rule
      assert.equals "example.com", fields.qname
      assert.equals "A", fields.qtype
      -- orientation client/résolveur correcte
      assert.equals "10.35.8.2", fields.src_ip
      assert.equals "1.1.1.1", fields.dst_ip
      -- temps présents dans la même table
      assert.equals 12, fields.q_to_response_ms
      assert.is_nil fields.delta_ms
      assert.equals 4, fields.question_proc_ms
      assert.equals 5, fields.response_entry_ms
      assert.equals 2, fields.parse_ms
      -- Mesures µs parallèles (non additives), présentes et en µs entières.
      assert.equals 1234, fields.ack_wait_us
      assert.equals 42, fields.log_write_us
      assert.equals "0x1f4d", fields.txid
      -- Les deux retries sont distincts : les champs IPC portent bien les
      -- valeurs IPC passées dans `info`, et ne sont pas les anciens noms nus.
      assert.equals 1, fields.ipc_retry_attempts
      assert.equals 3, fields.ipc_retry_wait_ms
      assert.is_nil fields.retry_attempts
      assert.is_nil fields.retry_wait_ms

    it "ack_wait_us et log_write_us valent 0 quand aucune mesure n'est fournie", ->
      m = fresh_worker_responses!
      entry = { refused: false, reason: "Allowed", rule_id: "r_ok", dnsonly: false }
      no_us = {
        delta_ms: 5, question_proc_ms: 1, response_entry_ms: 2, drain_ms: 0
        payload_ms: 1, parse_ms: 1, match_ms: 0, log_ms: 0
      }
      fields = m.build_benchmark_fields entry, info, no_us
      assert.equals 0, fields.ack_wait_us
      assert.equals 0, fields.log_write_us
      -- Les autres champs de la chaîne additive restent inchangés.
      assert.equals 5, fields.q_to_response_ms

    it "upstream_retries reflète entry.upstream_retries (compteur upstream)", ->
      m = fresh_worker_responses!
      entry = { refused: false, reason: "Allowed", rule_id: "r_ok", dnsonly: false, upstream_retries: 2 }
      fields = m.build_benchmark_fields entry, info, deltas
      assert.equals 2, fields.upstream_retries
      -- non-confusion : le retry IPC reste celui d'`info`, pas celui de l'upstream
      assert.equals 1, fields.ipc_retry_attempts
      assert.equals 3, fields.ipc_retry_wait_ms

    it "upstream_retries vaut 0 quand la transaction n'a pas été retentée", ->
      m = fresh_worker_responses!
      no_retry_info = {
        client_mac: "aa:bb:cc:dd:ee:ff", vlan: 8, client_ip: "10.35.8.2"
        resolver_ip: "1.1.1.1", client_port: 5353, txid: 0x1f4d, af: "ipv4"
        user: "alice@lan", qname: "example.com", qtype: "A"
        ipc_retry_attempts: 0, ipc_retry_wait_ms: 0
      }
      entry = { refused: false, reason: "Allowed", rule_id: "r_ok", dnsonly: false }
      fields = m.build_benchmark_fields entry, no_retry_info, deltas
      assert.equals 0, fields.upstream_retries
      assert.equals 0, fields.ipc_retry_attempts
      assert.equals 0, fields.ipc_retry_wait_ms

    it "verdict block quand entry.refused est vrai", ->
      m = fresh_worker_responses!
      entry = { refused: true, reason: "default deny", rule_id: "default_deny", dnsonly: false }
      fields, verdict = m.build_benchmark_fields entry, info, deltas
      assert.equals "block", verdict
      assert.equals "default_deny", fields.rule

  describe "format_block_event (blocage validateur amont)", ->
    ctx = {
      qname:       "emergent.sh"
      client_mac:  "e0:8f:4c:c8:91:fa"
      src_ip:      "10.35.99.38"
      dst_ip:      "1.1.1.3"
      vlan:        99
      user:        "j@prn.ovh"
      af:          "ipv4"
      nft_rule_id: "r_utilisateurs"
    }

    it "produit une ligne TSV block au format de worker_events", ->
      m = fresh_worker_responses!
      line = m.format_block_event ctx, 1781382351
      assert.equals "1781382351\tblock\temergent.sh\te0:8f:4c:c8:91:fa\t10.35.99.38\t1.1.1.3\t99\tj@prn.ovh\tipv4\tFiltered by upstream validator\tr_utilisateurs\n", line

    it "remplace les champs vides par '-' (compatible tsv_field)", ->
      m = fresh_worker_responses!
      line = m.format_block_event { qname: "x.com" }, 100
      fields = [f for f in line\gsub("\n", "")\gmatch "[^\t]+"]
      assert.equals "block", fields[2]
      assert.equals "x.com", fields[3]
      assert.equals "-", fields[4]          -- mac_src absent → "-"
      assert.equals "Filtered by upstream validator", fields[10]

    it "la décision est bien 'block' et exploitable par worker_events.process_line", ->
      m = fresh_worker_responses!
      we = require "worker_events"
      line = m.format_block_event ctx, 1781382351
      recent = {}
      assert.is_true we.process_line line\gsub("\n", ""), {}, recent
      assert.equals "emergent.sh", recent[1].qname
      assert.equals "e0:8f:4c:c8:91:fa", recent[1].mac

describe "worker_responses upstream retry", ->
  { parse: parse_ip, :s2ip } = require "ipparse.l3.ip"
  { parse: parse_udp } = require "ipparse.l4.udp"

  -- Paquet réponse IPv4/UDP (résolveur 1.1.1.1:53 → client 10.35.8.2:5353).
  build_response = (rcode) ->
    question = qname_example .. sp(">H H", QTYPE_A, QCLASS_IN)
    dns = sp(">H H H H H H", 0x1234, 0x8000 + rcode, 1, 0, 0, 0) .. question
    udp_len = 8 + #dns
    total = 20 + udp_len
    raw = sp ">B B H H H B B H", 0x45, 0, total, 0x1, 0, 64, 17, 0
    raw ..= s2ip("1.1.1.1") .. s2ip("10.35.8.2")
    raw ..= sp(">H H H H", 53, 5353, udp_len, 0) .. dns
    ip, _ = parse_ip raw, 1
    l4, _ = parse_udp raw, ip.data_off
    l4.proto = "udp"
    ip, l4, dns

  load_with_retry = (cfg) ->
    config = require "config"
    config.dns = { ttl_grace: { grace: 0, min: 60, max: 900 }, upstream_retry: cfg }
    config.ipc = { pending_ttl: 5 }
    sent = {}
    package.loaded["raw_send"] = {
      open: (ver) -> 40 + ver
      routable: -> true
      send: (fd, ver, pkt, dst) -> sent[#sent + 1] = { :fd, :ver, :pkt, :dst }
    }
    m = fresh_worker_responses!
    m.arm_retry_fds!
    m, sent

  mk_msg = (rcode) -> { header: { ra_z_rcode: rcode, qdcount: 1 }, questions: {{ name: "example.com" }} }

  it "réémet et renvoie true sur SERVFAIL dans le budget", ->
    m, sent = load_with_retry { enabled: true, max_attempts: 2, rcodes: { 2, 5 } }
    ip, l4, dns = build_response 2
    entry = { refused: false }
    assert.is_true (m.try_upstream_retry entry, mk_msg(2), dns, ip, l4, "1.1.1.1")
    assert.equals 1, entry.upstream_retries
    assert.equals 1, #sent
    assert.equals "1.1.1.1", sent[1].dst

  it "n'émet plus au-delà de max_attempts", ->
    m, sent = load_with_retry { enabled: true, max_attempts: 2, rcodes: { 2 } }
    ip, l4, dns = build_response 2
    assert.is_false (m.try_upstream_retry { refused: false, upstream_retries: 2 }, mk_msg(2), dns, ip, l4, "1.1.1.1")
    assert.equals 0, #sent

  it "ignore un rcode non listé (NXDOMAIN)", ->
    m, sent = load_with_retry { enabled: true, max_attempts: 2, rcodes: { 2, 5 } }
    ip, l4, dns = build_response 3
    assert.is_false (m.try_upstream_retry { refused: false }, mk_msg(3), dns, ip, l4, "1.1.1.1")
    assert.equals 0, #sent

  it "ne retry pas une transaction refused", ->
    m, sent = load_with_retry { enabled: true, max_attempts: 2, rcodes: { 2 } }
    ip, l4, dns = build_response 2
    assert.is_false (m.try_upstream_retry { refused: true }, mk_msg(2), dns, ip, l4, "1.1.1.1")

  it "désactivé par config → false", ->
    m, sent = load_with_retry { enabled: false }
    ip, l4, dns = build_response 2
    assert.is_false (m.try_upstream_retry { refused: false }, mk_msg(2), dns, ip, l4, "1.1.1.1")

  it "retente un NXDOMAIN tant que le budget le permet", ->
    m, sent = load_with_retry { enabled: true, max_attempts: 2, rcodes: { 2, 3, 5 } }
    ip, l4, dns = build_response 3
    entry = { refused: false }
    assert.is_true (m.try_upstream_retry entry, mk_msg(3), dns, ip, l4, "1.1.1.1")
    assert.equals 1, entry.upstream_retries
    assert.equals 1, #sent

  it "mémorise un nom durablement NXDOMAIN et n'y retente plus", ->
    m, sent = load_with_retry { enabled: true, max_attempts: 1, rcodes: { 3 } }
    ip, l4, dns = build_response 3
    -- budget épuisé (retries déjà à max) → marque le nom comme « mauvais »
    assert.is_false (m.try_upstream_retry { refused: false, upstream_retries: 1 }, mk_msg(3), dns, ip, l4, "1.1.1.1")
    -- nouvelle transaction, budget dispo, mais nom connu mauvais → pas de retry
    assert.is_false (m.try_upstream_retry { refused: false }, mk_msg(3), dns, ip, l4, "1.1.1.1")
    assert.equals 0, #sent

  it "une réponse NOERROR réhabilite un nom et autorise de nouveau le retry", ->
    m, sent = load_with_retry { enabled: true, max_attempts: 1, rcodes: { 3 } }
    ip3, l43, dns3 = build_response 3
    ip0, l40, dns0 = build_response 0
    assert.is_false (m.try_upstream_retry { refused: false, upstream_retries: 1 }, mk_msg(3), dns3, ip3, l43, "1.1.1.1")
    assert.is_false (m.try_upstream_retry { refused: false }, mk_msg(3), dns3, ip3, l43, "1.1.1.1")  -- connu mauvais
    assert.is_false (m.try_upstream_retry { refused: false }, mk_msg(0), dns0, ip0, l40, "1.1.1.1")  -- NOERROR réhabilite
    entry = { refused: false }
    assert.is_true (m.try_upstream_retry entry, mk_msg(3), dns3, ip3, l43, "1.1.1.1")   -- retry de nouveau permis
    assert.equals 1, entry.upstream_retries

describe "mac_clients / ip_to_mac (update_mac_clients, purge_mac_clients)", ->
  it "la purge d'une ancienne MAC ne supprime pas le mapping du nouveau propriétaire", ->
    m = fresh_worker_responses!
    -- MAC A voit X au temps 1
    m.update_mac_clients { mac_str: "aa:aa:aa:aa:aa:aa", ipv4: true, ip_str: "10.0.0.1" }, 1
    assert.equals "aa:aa:aa:aa:aa:aa", m.ip_to_mac["10.0.0.1"]
    -- MAC B prend X au temps 2
    m.update_mac_clients { mac_str: "bb:bb:bb:bb:bb:bb", ipv4: true, ip_str: "10.0.0.1" }, 2
    assert.equals "bb:bb:bb:bb:bb:bb", m.ip_to_mac["10.0.0.1"]
    -- A expire (302 - 1 > 300), B non (302 - 2 <= 300)
    m.purge_mac_clients 302
    assert.equals "bb:bb:bb:bb:bb:bb", m.ip_to_mac["10.0.0.1"]

  it "une MAC seule qui expire voit bien son IP retirée (contrôle)", ->
    m = fresh_worker_responses!
    m.update_mac_clients { mac_str: "cc:cc:cc:cc:cc:cc", ipv4: true, ip_str: "10.0.0.9" }, 1
    assert.equals "cc:cc:cc:cc:cc:cc", m.ip_to_mac["10.0.0.9"]
    m.purge_mac_clients 302
    assert.is_nil m.ip_to_mac["10.0.0.9"]

  it "changement d'IP d'une MAC ne supprime pas le mapping d'un autre propriétaire", ->
    m = fresh_worker_responses!
    m.update_mac_clients { mac_str: "aa:aa:aa:aa:aa:aa", ipv4: true, ip_str: "10.0.0.1" }, 1
    m.update_mac_clients { mac_str: "bb:bb:bb:bb:bb:bb", ipv4: true, ip_str: "10.0.0.1" }, 2
    -- A change d'IP : ne doit pas effacer ip_to_mac[10.0.0.1] (= B)
    m.update_mac_clients { mac_str: "aa:aa:aa:aa:aa:aa", ipv4: true, ip_str: "10.0.0.2" }, 3
    assert.equals "bb:bb:bb:bb:bb:bb", m.ip_to_mac["10.0.0.1"]
    assert.equals "aa:aa:aa:aa:aa:aa", m.ip_to_mac["10.0.0.2"]

-- ── Budget de retry d'appariement IPC (anti-amplification d'orphelins) ─────
-- Le retry bloquant (`count` × `sleep_ms`, 5 × 20 ms = 100 ms par défaut)
-- sérialisait le worker de réponses dans le hot-path NFQ : une rafale de
-- réponses orphelines le ramenait à ~10 réponses/s (100 % de temps en
-- nanosleep), vecteur de déni de service local. Le budget borne le sommeil
-- consommé par fenêtre d'une seconde ; au-delà, le retry est sauté (aucun
-- nanosleep) et la réponse est traitée comme orpheline.
ffi = require "ffi"
pcall ffi.cdef, [[
  int pipe2(int pipefd[2], int flags);
  int close(int fd);
  ssize_t read(int fd, void *buf, size_t count);
  int* __errno_location();
]]

describe "budget de retry d'appariement IPC", ->
  saved_match_retry = nil

  before_each ->
    config = require "config"
    config.ipc = config.ipc or {}
    saved_match_retry = config.ipc.match_retry

  after_each ->
    config = require "config"
    config.ipc.match_retry = saved_match_retry
    package.loaded["ipc"] = nil
    package.loaded["worker_responses"] = nil

  -- Recharge worker_responses avec une config match_retry donnée.
  load_with_match_retry = (retry_cfg) ->
    config = require "config"
    config.ipc = config.ipc or {}
    config.ipc.pending_ttl = 5
    config.ipc.match_retry = retry_cfg
    package.loaded["ipc"] = nil
    package.loaded["worker_responses"] = nil
    dofile "lua/worker_responses.lua"

  make_pipe = ->
    pipefd = ffi.new "int[2]"
    assert.equals 0, ffi.C.pipe2 pipefd, 2048  -- O_NONBLOCK
    { pipefd[0], pipefd[1] }

  describe "plan_retry_tries (fonction pure)", ->
    it "autorise toutes les tentatives quand le budget est intact", ->
      m = fresh_worker_responses!
      assert.equals 5, m.plan_retry_tries 0, 100, 20, 5

    it "borne les tentatives au budget restant", ->
      m = fresh_worker_responses!
      assert.equals 1, m.plan_retry_tries 80, 100, 20, 5
      assert.equals 4, m.plan_retry_tries 20, 100, 20, 5

    it "retourne 0 quand le budget restant est insuffisant", ->
      m = fresh_worker_responses!
      assert.equals 0, m.plan_retry_tries 85, 100, 20, 5
      assert.equals 0, m.plan_retry_tries 100, 100, 20, 5
      assert.equals 0, m.plan_retry_tries 0, 0, 20, 5

    it "ne borne pas les tentatives gratuites (sleep_ms = 0)", ->
      m = fresh_worker_responses!
      assert.equals 5, m.plan_retry_tries 1000, 100, 0, 5

    it "ne dépasse jamais le nombre de tentatives configuré", ->
      m = fresh_worker_responses!
      assert.equals 2, m.plan_retry_tries 0, 100000, 20, 2

  describe "retry_pending_match borné", ->
    it "une rafale ne consomme qu'un budget par seconde puis saute le retry", ->
      m = load_with_match_retry { enabled: true, count: 5, sleep_ms: 20, budget_ms: 100 }
      p = make_pipe!
      m._set_pipe_rfd p[1]
      -- Aucune question en attente : les tentatives ne peuvent pas apparier.
      entry1, attempts1, wait1, skipped1 = m.retry_pending_match 0x1234, "10.0.0.2", 5353, "1.1.1.1", 1000
      assert.is_nil entry1
      assert.equals 5, attempts1, "budget intact : les 5 tentatives configurées ont lieu"
      assert.equals 100, wait1
      assert.is_false skipped1
      -- Budget de la seconde épuisé : la tentative suivante est SAUTÉE, sans
      -- sommeil (avant correctif : 5 tentatives et 100 ms de plus, en série).
      entry2, attempts2, wait2, skipped2 = m.retry_pending_match 0x1234, "10.0.0.2", 5353, "1.1.1.1", 1000
      assert.is_nil entry2
      assert.equals 0, attempts2, "retry sauté : aucun nanosleep"
      assert.equals 0, wait2, "aucun sommeil consommé"
      assert.is_true skipped2, "budget_skipped signale la borne atteinte"
      -- Nouvelle fenêtre (seconde suivante) : le budget est réinitialisé.
      _, attempts3, _, skipped3 = m.retry_pending_match 0x1234, "10.0.0.2", 5353, "1.1.1.1", 1001
      assert.equals 5, attempts3
      assert.is_false skipped3
      ffi.C.close p[1]
      ffi.C.close p[2]

    it "préserve le retry du cas nominal (réordonnancement IPC absorbé)", ->
      m = load_with_match_retry { enabled: true, count: 5, sleep_ms: 20, budget_ms: 100 }
      ipc = require "ipc"
      p = make_pipe!
      m._set_pipe_rfd p[1]
      -- La question arrive dans le pipe APRÈS le paquet de réponse : c'est le
      -- réordonnancement légitime que le retry doit absorber.
      ipc.write_msg p[2], 0x1234, "\x0a\x00\x00\x02", 5353,
                   "\xaa\xbb\xcc\xdd\xee\xff", "\x01\x01\x01\x01", "ok", nil, "r_ok"
      entry, attempts, wait, skipped = m.retry_pending_match 0x1234, "10.0.0.2", 5353, "1.1.1.1", 1000
      assert.is_not_nil entry, "la question est appariée après le premier drain"
      assert.equals 1, attempts
      assert.equals 20, wait
      assert.is_false skipped
      assert.equals "r_ok", entry.rule_id
      -- Le budget a été débité du sommeil réellement consommé.
      assert.equals 20, m._retry_budget.used_ms
      ffi.C.close p[1]
      ffi.C.close p[2]

-- ── Observabilité du non-appariement (réponse orpheline jetée) ─────────────
-- Avant correctif, le seul témoin d'une réponse client perdue était un log
-- DEBUG : muet en production (`log_level: "INFO"`). La trace est désormais
-- émise en INFO via `build_orphan_fields`, dont le débit est borné par
-- log.moon (RL_CONFIG.response_orphan_dropped, vérifié dans log_spec).
describe "build_orphan_fields (trace INFO du drop orphelin)", ->
  base_info = {
    src_ip: "1.1.1.1"
    dst_ip: "10.0.0.2"
    dst_port: 5353
    vlan: 8
    txid: "0x1234"
    qname: "example.com"
    rcode: 0
    client_mac: "aa:bb:cc:dd:ee:ff"
    user: "alice@lan"
    ipc_retry_attempts: 0
    ipc_retry_wait_ms: 0
    retry_budget_skipped: false
  }

  it "produit une action dédiée avec les champs d'enquête", ->
    m = fresh_worker_responses!
    f = m.build_orphan_fields base_info
    assert.equals "response_orphan_dropped", f.action
    assert.equals "0x1234",    f.txid
    assert.equals "10.0.0.2",  f.dst_ip
    assert.equals 5353,        f.dst_port
    assert.equals "1.1.1.1",   f.src_ip
    assert.equals "example.com", f.qname
    assert.equals "aa:bb:cc:dd:ee:ff", f.client_mac
    assert.equals 8,           f.vlan
    assert.equals 0,           f.rcode
    assert.equals 0,           f.retry_budget_skipped

  it "traduit le budget épuisé et les compteurs de retry", ->
    m = fresh_worker_responses!
    info = {}
    info[k] = v for k, v in pairs base_info
    info.retry_budget_skipped = true
    info.ipc_retry_attempts = 2
    info.ipc_retry_wait_ms = 40
    f = m.build_orphan_fields info
    assert.equals 1,  f.retry_budget_skipped, "budget épuisé signalé dans la trace"
    assert.equals 2,  f.ipc_retry_attempts
    assert.equals 40, f.ipc_retry_wait_ms

  it "qname absent → '-' (jamais nil dans la ligne)", ->
    m = fresh_worker_responses!
    info = {}
    info[k] = v for k, v in pairs base_info
    info.qname = nil
    assert.equals "-", (m.build_orphan_fields info).qname

describe "verdicts différés par lot NFQUEUE (settle / flush_deferred)", ->
  calls = nil
  m = nil

  before_each ->
    m = fresh_worker_responses!
    calls = { set: {}, waits: {}, seq_reads: 0, seq: nil }
    m._set_defer_deps {
      get_last_seq: ->
        calls.seq_reads += 1
        calls.seq
      wait_ack: (seq, corr, on_wait) ->
        calls.waits[#calls.waits + 1] = { :seq, :corr }
        true
      set_verdict: (qh, id, verdict, payload) ->
        calls.set[#calls.set + 1] = { :qh, :id, :verdict, :payload }
    }

  it "en mode lot, settle mémorise le verdict sans attente ni verdict posé", ->
    ctx = { qh_ptr: "qh", pkt_id: 11, ack_corr: "c1", defer: true }
    m.settle ctx, 1, nil, true
    m.settle ctx, 1, "payload", true
    assert.equals 2, m.deferred_count!
    assert.equals 0, #calls.set
    assert.equals 0, #calls.waits
    assert.equals 0, calls.seq_reads

  it "flush_deferred pose tous les verdicts après UN SEUL ACK du plus grand seq", ->
    ctx1 = { qh_ptr: "qh", pkt_id: 11, ack_corr: "c1", defer: true }
    ctx2 = { qh_ptr: "qh", pkt_id: 12, ack_corr: "c2", defer: true }
    m.settle ctx1, 1, nil, true
    m.settle ctx2, 1, "patched", true
    calls.seq = 42
    n = m.flush_deferred!
    assert.equals 2, n
    assert.equals 1, #calls.waits
    assert.equals 42, calls.waits[1].seq
    assert.equals "c2", calls.waits[1].corr
    assert.equals 2, #calls.set
    assert.equals 11, calls.set[1].id
    assert.is_nil calls.set[1].payload
    assert.equals 12, calls.set[2].id
    assert.equals "patched", calls.set[2].payload
    assert.equals 0, m.deferred_count!

  it "flush_deferred sans insertion enfilée (seq nil) ne fait aucune attente", ->
    ctx = { qh_ptr: "qh", pkt_id: 7, ack_corr: "c", defer: true }
    m.settle ctx, 1, nil, false
    n = m.flush_deferred!
    assert.equals 1, n
    assert.equals 0, #calls.waits
    assert.equals 1, #calls.set

  it "flush_deferred vide ne fait rien", ->
    assert.equals 0, m.flush_deferred!
    assert.equals 0, calls.seq_reads
    assert.equals 0, #calls.set

  it "hors lot, settle attend une fois puis pose le verdict", ->
    ctx = { qh_ptr: "qh", pkt_id: 3, ack_corr: "corr" }
    calls.seq = 9
    m.settle ctx, 1, nil, true
    assert.equals 1, #calls.waits
    assert.equals 9, calls.waits[1].seq
    assert.equals "corr", calls.waits[1].corr
    assert.equals 1, #calls.set
    assert.equals 3, calls.set[1].id

  it "hors lot, settle sans insertion à acquitter ne fait aucune attente", ->
    ctx = { qh_ptr: "qh", pkt_id: 4, ack_corr: "corr" }
    calls.seq = 9
    m.settle ctx, 1, "patched", false
    assert.equals 0, #calls.waits
    assert.equals 1, #calls.set
    assert.equals "patched", calls.set[1].payload

  it "une erreur du chemin de verdict est journalisée, pas propagée", ->
    ctx = { qh_ptr: "qh", pkt_id: 8, ack_corr: "c", defer: true }
    m.settle ctx, 1, nil, true
    m._set_defer_deps {
      get_last_seq: -> 1
      wait_ack: -> true
      set_verdict: -> error "boom"
    }
    n = m.flush_deferred!
    assert.equals 1, n
    assert.equals 0, m.deferred_count!

  it "hors lot, dnsonly avec insertion captive_probe attend l'ACK", ->
    ctx = { qh_ptr: "qh", pkt_id: 5, ack_corr: "corr", dnsonly: true }
    calls.seq = 9
    m.settle ctx, 1, nil, true
    assert.equals 1, #calls.waits
    assert.equals 1, #calls.set

describe "worker_responses helpers complémentaires (couverture)", ->
  before_each ->
    config = require "config"
    config.ipc = config.ipc or {}
    config.ipc.match_retry = { enabled: true, count: 5, sleep_ms: 0, budget_ms: 100 }

  it "format_block_event sans timestamp utilise os.time", ->
    m = fresh_worker_responses!
    line = m.format_block_event { qname: "exemple.test" }
    assert.truthy line\match "^%d+\tblock\t"
    assert.truthy line\match "exemple.test"
    assert.equals "exemple.test", (line\gsub("\n", ""))\match "\tblock\t([^\t]+)"

  it "update_mac_clients : changement d'IPv6 oublie l'ancien mapping de cette MAC", ->
    m = fresh_worker_responses!
    m.update_mac_clients { mac_str: "aa:aa:aa:aa:aa:aa", ip_str: "2001:db8::1" }, 1
    assert.equals "aa:aa:aa:aa:aa:aa", m.ip_to_mac["2001:db8::1"]
    m.update_mac_clients { mac_str: "aa:aa:aa:aa:aa:aa", ip_str: "2001:db8::2" }, 2
    assert.is_nil m.ip_to_mac["2001:db8::1"]
    assert.equals "aa:aa:aa:aa:aa:aa", m.ip_to_mac["2001:db8::2"]

  it "update_mac_clients ignore la MAC nulle (inconnue)", ->
    m = fresh_worker_responses!
    m.update_mac_clients { mac_str: "00:00:00:00:00:00", ipv4: true, ip_str: "10.0.0.1" }, 1
    assert.is_nil m.ip_to_mac["10.0.0.1"]

  it "maybe_dynamic_strip sans entrée ou sans rr_code renvoie la réponse intacte", ->
    m = fresh_worker_responses!
    raw = "payload"
    assert.same { raw, false }, { m.maybe_dynamic_strip("a.test", raw, -> nil) }
    assert.same { raw, false }, { m.maybe_dynamic_strip(nil, raw, -> 3) }

  it "_reset_deferred vide la file de verdicts différés", ->
    m = fresh_worker_responses!
    m.settle { qh_ptr: "qh", pkt_id: 1, defer: true }, 1, nil, false
    assert.equals 1, m.deferred_count!
    m._reset_deferred!
    assert.equals 0, m.deferred_count!
    assert.equals 0, m.flush_deferred!

  it "retry_pending_match est inactif si le retry est désactivé", ->
    config = require "config"
    config.ipc.match_retry = { enabled: false, count: 5, sleep_ms: 0 }
    m = fresh_worker_responses!
    entry, tries, waited, budget = m.retry_pending_match "tx", "10.0.0.1", 1, "1.1.1.1", 10
    assert.is_nil entry
    assert.equals 0, tries
    assert.equals 0, waited
    assert.is_false budget

  it "retry_pending_match est inactif si count vaut 0", ->
    config = require "config"
    config.ipc.match_retry = { enabled: true, count: 0, sleep_ms: 0 }
    m = fresh_worker_responses!
    entry, tries, waited, budget = m.retry_pending_match "tx", "10.0.0.1", 1, "1.1.1.1", 10
    assert.is_nil entry
    assert.equals 0, tries
    assert.equals 0, waited
    assert.is_false budget
