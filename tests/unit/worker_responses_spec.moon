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
      retry_wait_ms:  3
      retry_attempts: 1
    }
    deltas = {
      delta_ms: 12, question_proc_ms: 4, response_entry_ms: 5, drain_ms: 0
      payload_ms: 1, parse_ms: 2, match_ms: 0, log_ms: 0
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
      assert.equals "0x1f4d", fields.txid

    it "verdict block quand entry.refused est vrai", ->
      m = fresh_worker_responses!
      entry = { refused: true, reason: "default deny", rule_id: "default_deny", dnsonly: false }
      fields, verdict = m.build_benchmark_fields entry, info, deltas
      assert.equals "block", verdict
      assert.equals "default_deny", fields.rule

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
    ip, _ = parse_ip raw
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
