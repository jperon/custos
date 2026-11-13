-- tests/unit/worker_responses_finalize_spec.moon
-- T6 : finalize_a — branches d'override validateur (block/sinkhole/redirect),
-- chemin pass et fail-closed nft. Verdict capturé via un faux nfq_set_verdict ;
-- inject / dns_classify / nft_queue / filter stubbés localement et restaurés.

ffi = require "ffi"
bit = require "bit"
sp  = require("ipparse.lib.pack_compat").pack
{ :s2ip } = require "ipparse.l3.ip"
dns_mod = require "ipparse.l7.dns"
packet_utils = require "packet_utils"

-- cdef minimal pour mesurer l'attente ACK (ffi_defs est stubbé sur ffi.C).
pcall ->
  ffi.cdef "int clock_gettime(int clk_id, timespec_t *tp);"

QTYPE_A = dns_mod.types.A
QCLASS_IN = dns_mod.classes.IN
QNAME = "\7example\3com\0"

make_dns_response = ->
  question = QNAME .. sp(">H H", QTYPE_A, QCLASS_IN)
  answer = "\192\012" .. sp(">H H I4 s2", QTYPE_A, QCLASS_IN, 60, "\1\2\3\4")
  sp(">H H H H H H", 0x1234, 0x8180, 1, 1, 0, 0) .. question .. answer

ipv4_udp = (dns) ->
  udp_len = 8 + #dns
  total   = 20 + udp_len
  hdr = sp ">B B H H H B B H", 0x45, 0, total, 0x1234, 0, 64, 17, 0
  hdr ..= s2ip("1.1.1.1") .. s2ip("192.0.2.10")
  hdr .. sp(">H H H H", 53, 5353, udp_len, 0) .. dns

STUB_KEYS = {
  "ffi_defs", "worker_responses", "response_inject", "dns_classify"
  "nft_queue", "filter"
}
saved = {}

describe "worker_responses.finalize_a", ->

  m = nil
  verdicts = {}
  injected = {}
  probe_calls = {}
  state = {}
  dns_msg = nil
  raw = nil
  ctx = nil

  before_each ->
    saved[k] = package.loaded[k] for k in *STUB_KEYS
    verdicts = {}
    injected = {}
    probe_calls = {}
    state = { has_cname: false }

    -- Benchmark actif : exerce les mesures µs (attente ACK). Sans effet sur
    -- les autres cas, qui n'appellent pas wait_ack (last_seq nil).
    config = require "config"
    config.runtime = { benchmark: true }

    package.loaded["ffi_defs"] = {
      :ffi
      libc: ffi.C
      libnfq: {
        nfq_set_verdict: (qh, id, verdict, len, ptr) ->
          verdicts[#verdicts + 1] = {
            :id, :verdict, :len
            payload: (len > 0 and ptr != nil) and ffi.string(ptr, len) or nil
          }
          0
      }
    }
    package.loaded["response_inject"] = {
      rr_timeout: -> nil
      detect_wildcards: -> {}
      inject: (answers, opts) ->
        injected[#injected + 1] = answers
        state.inject_result
    }
    package.loaded["dns_classify"] = {
      has_cname_target: (dns, raw_dns, target) -> state.has_cname
      cname_targets: -> {}
    }
    package.loaded["nft_queue"] = {
      add_ip4: (-> nil), add_ip6: (-> nil)
      add_mac4: (mac, ip, rule_id, timeout, corr) ->
        probe_calls[#probe_calls + 1] = {
          family: "mac4", :mac, :ip, :rule_id, :timeout, :corr
        }
        state.probe_add_ok != false
      add_mac6: (mac, ip, rule_id, timeout, corr) ->
        probe_calls[#probe_calls + 1] = {
          family: "mac6", :mac, :ip, :rule_id, :timeout, :corr
        }
        state.probe_add_ok != false
      get_last_seq: -> state.last_seq
      wait_ack: (seq, corr, on_wait) ->
        state.wait_calls = (state.wait_calls or 0) + 1
        state.wait_fn seq, corr if state.wait_fn
        true
      drain_ack: -> nil
    }
    package.loaded["filter"] = {
      run_on_response: (rule_id, dns_raw, reason, extra) ->
        { dns_raw: dns_raw, modified: false, inject_nft: false }
    }
    state.inject_result = {
      ip_count: 1, records_to_add: 1, success_any: true
      no_v4: {}, no_v6: {}
    }

    package.loaded["worker_responses"] = nil
    m = require "worker_responses"

    raw = ipv4_udp make_dns_response!
    ip, l4, dns_parsed, dns_raw, ip_ihl = packet_utils.parse_dns_packet raw, packet_utils.new_dns_tcp_stream!
    assert.equals 4, ip.version
    dns_msg = dns_parsed

    ctx = {
      qh_ptr: nil, pkt_id: 42
      :raw, :ip, :l4, :dns_msg, :dns_raw, :ip_ihl
      entry: { refused: false, reason: "Allowed by rule: test", rule_id: "r1", dnsonly: false }
      resolver_ip: "1.1.1.1"
      dnsonly: false
      nft_rule_id: "r1"
      ack_corr: nil
      client_ip: "192.0.2.10"
      client_mac: "aa:bb:cc:dd:ee:ff"
      user: nil
      txid: 0x1234
      vlan: nil
      src_ip: "1.1.1.1"
      dst_ip: "192.0.2.10"
      qname: "example.com"
      af: "ipv4"
    }

  after_each ->
    for k in *STUB_KEYS
      package.loaded[k] = saved[k]

  -- Payload DNS d'un paquet verdict (IPv4 + UDP : 20 + 8 octets d'en-tête),
  -- et code retour lu dans les 4 premiers bits du drapeau bas.
  dns_of = (payload) -> payload\sub 29
  rcode_of = (payload) -> bit.band dns_of(payload)\byte(4), 0x0f

  it "override block → NXDOMAIN + EDE, verdict NF_ACCEPT avec payload", ->
    m.finalize_a ctx, { kind: "block" }
    assert.equals 1, #verdicts
    call = verdicts[1]
    assert.equals 42, call.id
    assert.equals 1, call.verdict
    assert.is_not_nil call.payload
    assert.equals dns_mod.rcodes.NXDOMAIN, rcode_of call.payload
    dns = dns_mod.parse dns_of(call.payload), 1, false
    assert.equals 0, #dns.answers
    assert.is_not_nil call.payload\find "Ne intretis", 1, true

  it "override sinkhole → NOERROR 0.0.0.0 + EDE, verdict NF_ACCEPT", ->
    m.finalize_a ctx, { kind: "sinkhole", a: { "\0\0\0\0" }, aaaa: {}, ttl: 60 }
    assert.equals 1, #verdicts
    call = verdicts[1]
    assert.equals 1, call.verdict
    assert.equals dns_mod.rcodes.NOERROR, rcode_of call.payload
    dns = dns_mod.parse dns_of(call.payload), 1, false
    assert.equals 1, #dns.answers
    assert.equals QTYPE_A, dns.answers[1].rtype
    assert.equals "\0\0\0\0", dns.answers[1].rdata

  it "override redirect → CNAME cible, IPs injectées et verdict NF_ACCEPT", ->
    m.finalize_a ctx, {
      kind: "redirect"
      cname_target: "portal.example"
      a: { "\192\0\2\99" }
      aaaa: {}
      ttl: 60
    }
    assert.equals 1, #verdicts
    call = verdicts[1]
    assert.equals 1, call.verdict
    assert.equals dns_mod.rcodes.NOERROR, rcode_of call.payload
    dns = dns_mod.parse dns_of(call.payload), 1, false
    assert.equals dns_mod.types.CNAME, dns.answers[1].rtype
    assert.equals 1, #injected
    assert.equals "ipv4", injected[1][1].family
    assert.equals "192.0.2.99", injected[1][1].addr

  it "redirect avec le CNAME déjà présent → passthrough (sans payload)", ->
    state.has_cname = true
    m.finalize_a ctx, {
      kind: "redirect"
      cname_target: "portal.example"
      a: { "\192\0\2\99" }
      ttl: 60
    }
    assert.equals 1, #verdicts
    assert.equals 1, verdicts[1].verdict
    assert.is_nil verdicts[1].payload
    assert.equals 1, #injected

  it "chemin pass sans modification → NF_ACCEPT sans payload", ->
    m.finalize_a ctx, nil
    assert.equals 1, #verdicts
    assert.equals 1, verdicts[1].verdict
    assert.is_nil verdicts[1].payload
    -- La réponse A est tout de même injectée dans nft.
    assert.equals 1, #injected
    assert.equals 1, #injected[1]

  it "échec d'ajout nft → NF_DROP (fail-closed)", ->
    state.inject_result = {
      ip_count: 0, records_to_add: 1, success_any: false
      no_v4: {}, no_v6: {}
    }
    m.finalize_a ctx, nil
    assert.equals 1, #verdicts
    assert.equals 0, verdicts[1].verdict
    assert.is_nil verdicts[1].payload

  -- ── Sondes de portail captif (action dnsonly) ─────────────────
  -- Une réponse dnsonly ne doit rien injecter pour l'accès, mais sa
  -- destination est mémorisée dans les sets captive_probe_mac4/6, consommés
  -- par la règle nft placée AVANT le dispatch (IP de sonde partagée avec un
  -- CDN autorisé par une autre règle, cf. docs/agents/filtre.md).
  it "réponse dnsonly → destination mémorisée dans captive_probe (MAC, ACK attendu)", ->
    state.inject_result = {
      ip_count: 0, records_to_add: 0, success_any: false
      no_v4: {}, no_v6: {}
    }
    state.last_seq = 9
    ctx.dnsonly = true
    ctx.entry.dnsonly = true
    m.finalize_a ctx, nil
    assert.equals 1, #verdicts
    assert.equals 1, verdicts[1].verdict
    assert.equals 1, #probe_calls
    call = probe_calls[1]
    assert.equals "mac4", call.family
    assert.equals "aa:bb:cc:dd:ee:ff", call.mac
    assert.equals "1.2.3.4", call.ip
    assert.equals "captive_probe", call.rule_id
    assert.equals 1, state.wait_calls

  it "réponse non dnsonly → aucune insertion captive_probe", ->
    state.inject_result = {
      ip_count: 0, records_to_add: 0, success_any: false
      no_v4: {}, no_v6: {}
    }
    m.finalize_a ctx, nil
    assert.equals 1, #verdicts
    assert.equals 0, #probe_calls

  it "échec d'insertion captive_probe → réponse tout de même NF_ACCEPT", ->
    state.inject_result = {
      ip_count: 0, records_to_add: 0, success_any: false
      no_v4: {}, no_v6: {}
    }
    state.probe_add_ok = false
    ctx.dnsonly = true
    ctx.entry.dnsonly = true
    m.finalize_a ctx, nil
    assert.equals 1, #verdicts
    assert.equals 1, verdicts[1].verdict
    assert.equals 1, #probe_calls

  -- ── Mesure µs de l'attente d'ACK (benchmark) ─────────────────
  it "mesure wait_ack en microsecondes et la remet à zéro après prise", ->
    state.last_seq = 7
    state.wait_fn = ->
      sreq = ffi.new "timespec_t[1]"
      sreq[0].tv_sec = 0
      sreq[0].tv_nsec = 2000000   -- 2 ms
      ffi.C.nanosleep sreq, nil
    m.finalize_a ctx, nil
    assert.equals 1, state.wait_calls
    us = m.take_last_ack_wait_us!
    assert.equals "number", type us
    assert.is_true us >= 1000, "attente de 2 ms attendue, mesuré #{us} µs"
    assert.is_true us < 150000, "mesure aberrante : #{us} µs"
    -- Une mesure n'est reportée qu'une fois (consommée par la ligne suivante).
    assert.equals 0, m.take_last_ack_wait_us!

  it "take_last_ack_wait_us vaut 0 quand aucun wait_ack n'a eu lieu", ->
    state.last_seq = nil
    m.finalize_a ctx, nil
    assert.is_nil state.wait_calls
    assert.equals 0, m.take_last_ack_wait_us!

  it "mode nominal (benchmark off) : wait_ack appelé sans mesure (0)", ->
    config = require "config"
    config.runtime = { benchmark: false }
    package.loaded["worker_responses"] = nil
    m_off = require "worker_responses"
    state.last_seq = 7
    m_off.finalize_a ctx, nil
    assert.equals 1, state.wait_calls
    assert.equals 0, m_off.take_last_ack_wait_us!

  it "finalize_a alloue < 3550 o par appel (GC arrêté)", ->
    -- finalize_a créait 3 closures par paquet (client_addr, inject_answers,
    -- patch_and_accept) + la table inject_opts (11 clés) : cf.
    -- docs/agents/perf.md §22. Seuil calibré sur la mesure GC arrêté dans
    -- ce harnais (3897 → 3277 ; le strip scratch de dns_ede porte à 2710).
    state.last_seq = nil
    config = require "config"
    config.runtime = { benchmark: false }
    package.loaded["worker_responses"] = nil
    m = require "worker_responses"
    for _ = 1, 500 do m.finalize_a ctx, nil   -- JIT + caches
    verdicts = {}
    collectgarbage "collect"
    collectgarbage "stop"
    before = collectgarbage "count"
    for _ = 1, 200
      verdicts = {}
      m.finalize_a ctx, nil
    after = collectgarbage "count"
    collectgarbage "restart"
    per_call = (after - before) * 1024 / 200
    assert.is_true per_call < 3550,
      "finalize_a alloue #{math.floor per_call} o/appel (seuil 3550)"
