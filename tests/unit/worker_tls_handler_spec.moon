-- tests/unit/worker_tls_handler_spec.moon
-- Couverture du handler NFQUEUE de worker_tls (handle_sni_packet), du point
-- d'entrée run() et des helpers de formatage/version/log restés hors des
-- specs existantes.
--
-- Le module est rechargé avec des stubs locaux (ffi_defs, nfq_loop,
-- nfq/ethernet, filter, auth.sessions, nft_queue, nft) restaurés après chaque
-- test : même méthode que tests/unit/worker_questions_spec.moon, pour ne pas
-- laisser fuiter d'état FFI global entre specs.

ffi = require "ffi"
bit = require "bit"
{ :rshift, :band } = bit
sp = require("ipparse.lib.pack_compat").pack
{ :s2ip } = require "ipparse.l3.ip"

-- __errno_location est lu par worker_tls uniquement via ses dépendances ; on
-- déclare le symbole pour les stubs qui l'utilisent (idempotent).
pcall ffi.cdef, "int* __errno_location(void);"


quic_fixture = io.open "tests/e2e/fixtures/quic_initial.bin", "rb"
QUIC_INITIAL = quic_fixture\read "*a"
quic_fixture\close!

u16 = (n) -> string.char rshift(n, 8), band(n, 0xFF)
u24 = (n) -> string.char band(rshift(n, 16), 0xFF), band(rshift(n, 8), 0xFF), band(n, 0xFF)

make_sni_ext = (hostname) ->
  name_len = #hostname
  list_len = name_len + 3
  table.concat {
    u16 0x0000
    u16 list_len + 2
    u16 list_len
    string.char 0x00
    u16 name_len
    hostname
  }

make_supported_versions_ext = (versions={0x0304}) ->
  body = string.char #versions * 2
  parts = { body }
  for v in *versions
    parts[#parts + 1] = string.char band(rshift(v, 8), 0xFF), band(v, 0xFF)
  body = table.concat parts
  table.concat { u16(0x002b), u16(#body), body }

-- ClientHello complet. `ext_len_override` permet de déclarer une longueur
-- d'extensions plus grande que la réalité : le parseur strict (ipparse) échoue
-- alors que le repli tolérant, qui borne à #payload, retrouve le SNI.
build_client_hello = (extensions_bin, opts={}) ->
  ch_body = table.concat {
    string.char 0x03, 0x03
    string.rep "\0", 32
    string.char 0x00
    string.char 0x00, 0x02, 0x13, 0x01
    string.char 0x01, 0x00
    u16 (opts.ext_len_override or #extensions_bin)
    extensions_bin
  }
  hs = string.char(opts.hs_type or 0x01) .. u24(#ch_body) .. ch_body
  table.concat {
    string.char opts.record_type or 0x16
    string.char 0x03, 0x03
    u16 #hs
    hs
  }

ipv4_packet = (proto, l4, opts={}) ->
  total = 20 + #l4
  hdr = sp(">B B H H H B B H", 0x45, 0, total, 0x1234, 0, 64, proto, 0) ..
    s2ip(opts.src or "192.0.2.10") .. s2ip(opts.dst or "93.184.216.34")
  hdr .. l4

ipv4_tcp = (payload, opts={}) ->
  header_len = opts.header_len or 0x50
  options = string.rep "\0", opts.tcp_options or 0
  tcp = sp(">H H I4 I4 B B H H H",
    opts.sport or 50000, opts.dport or 443, opts.seq or 1000, 0,
    header_len, opts.flags or 0x18, 8192, 0, 0) .. options
  ipv4_packet 6, tcp .. payload, opts

ipv4_udp = (payload, opts={}) ->
  udp = sp(">H H H H", opts.sport or 50000, opts.dport or 443, 8 + #payload, 0) .. payload
  ipv4_packet 17, udp, opts

push_fail = (payload) -> false, "push boom"

ipv6_tcp = (payload, opts={}) ->
  tcp = sp(">H H I4 I4 B B H H H",
    opts.sport or 50000, opts.dport or 443, opts.seq or 1000, 0,
    0x50, opts.flags or 0x18, 8192, 0, 0)
  total = #tcp + #payload
  hdr = string.char(0x60, 0, 0, 0) .. sp(">H B B", total, 6, 64) ..
    s2ip("2001:db8::1") .. s2ip("2001:db8::2")
  hdr .. tcp .. payload

split_tabs = (line) ->
  out = {}
  for f in (line\gsub("\n$", ""))\gmatch "[^\t]+"
    out[#out + 1] = f
  out

STUB_KEYS = {
  "ffi_defs", "nfq_loop", "nfq/ethernet", "filter", "auth.sessions"
  "nft_queue", "nft", "worker_tls", "ipparse.l7.quic.session", "_filtered_stub"
}
saved = {}
save_all = ->
  saved[k] = package.loaded[k] for k in *STUB_KEYS
restore_all = ->
  for k in *STUB_KEYS
    package.loaded[k] = saved[k]

-- État contrôlable par les tests.
payload_raw = nil
payload_buf = nil
l2_result = nil
decide_result = nil
decide_throws = false
filter_has_decide = true
sni_cfg = nil
events_out = {}
nft_cmds = {}
nft_ok = true
nft_err = nil
mark_rc = 0
mark_calls = {}
run_cb = nil
user_name = "alice"

install_stubs = ->
  package.loaded["ffi_defs"] = {
    :ffi
    libc: {
      write: (fd, buf, n) ->
        events_out[#events_out + 1] = ffi.string buf, n
        n
    }
    libnfq: {
      nfq_get_payload: (nfad, ptr) ->
        return 0 unless payload_raw
        buf = ffi.new "uint8_t[?]", #payload_raw
        ffi.copy buf, payload_raw, #payload_raw
        payload_buf = buf   -- référence Lua vivante pendant le handler
        ptr[0] = ffi.cast "unsigned char*", buf
        #payload_raw
    }
  }

  package.loaded["nfq_loop"] = {
    NF_ACCEPT: 1
    NF_DROP: 0
    VERDICT_DONE: -1
    run_queue: (q, cb) -> run_cb = cb
    set_verdict_marked: (qh, pkt_id, verdict, mark) ->
      mark_calls[#mark_calls + 1] = { :qh, :pkt_id, :verdict, :mark }
      mark_rc
  }

  package.loaded["nfq/ethernet"] = { get_l2: -> l2_result }

  filtered = {}
  filtered.get_auth_cfg = -> { sessions_file: "tmp/unused_sessions.lua" }
  filtered.get_sni_cfg = -> sni_cfg
  filtered.decide_meta = (req) ->
    filtered.last_req = req
    error "decide boom" if decide_throws
    decide_result
  package.loaded["filter"] = filtered
  package.loaded["_filtered_stub"] = filtered

  package.loaded["auth.sessions"] = {
    user_for_mac: (mac, ip, path) -> user_name
  }

  package.loaded["nft_queue"] = {
    cmd_for: (kind, src, dst, rule_id, ttl) ->
      "#{kind} #{src} #{dst} #{rule_id} #{ttl}"
  }
  package.loaded["nft"] = {
    run_cmd: (cmd, opts) ->
      nft_cmds[#nft_cmds + 1] = cmd
      nft_ok, nft_err
  }


-- Chargé une fois par test (comme worker_questions_spec) pour capturer les
-- stubs au moment du require.
load_worker = ->
  package.loaded["worker_tls"] = nil
  w = require "worker_tls"
  w.set_validator_state {
    validator_mod: false, cname_mod: false
    second_opinion_cfg: false, filter_cfg: false
  }
  w

describe "worker_tls handler NFQUEUE", ->
  w = nil

  lazy_setup ->
    save_all!
    sni_cfg = { enabled: true, mode: "strict-443", protocols: "both" }
    install_stubs!
    w = load_worker!
    w.run 0, 42

  lazy_teardown ->
    restore_all!

  before_each ->
    payload_raw = nil
    payload_buf = nil
    l2_result = { mac_raw: "\170\187\204\221\238\255", vlan: 7 }
    decide_result = nil
    decide_throws = false
    filter_has_decide = true
    sni_cfg = { enabled: true, mode: "strict-443", protocols: "both" }
    events_out = {}
    nft_cmds = {}
    nft_ok = true
    nft_err = nil
    mark_rc = 0
    mark_calls = {}
    run_cb = nil
    user_name = "alice"
    -- Les stubs sont réinstallés (tables fraîches) avant chaque test : run()
    -- récupère le filtre courant, et les tests qui mutent une table de module
    -- (nft_queue, session QUIC) partent d'un état propre.
    install_stubs!
    w.reset_tcp_sessions!
    w.reset_quic_sessions!
    w.reset_sni_verdicts!
    w.reset_nft_modules!
    -- `set_validator_state` ignore nil (« laisser inchangé ») : on remet
    -- explicitement chaque dépendance à false pour isoler les tests.
    w.set_validator_state {
      validator_mod: false, cname_mod: false
      second_opinion_cfg: false, filter_cfg: false
    }
    w.run 0, 42
    run_cb = nil

  invoke = -> w.handle_sni_packet nil, nil, 123

  describe "garde-fous d'entrée", ->
    it "L2 absent → NF_ACCEPT", ->
      l2_result = nil
      payload_raw = ipv4_udp "\x01\x02\x03\x04\x05"
      assert.equals 1, invoke!

    it "payload vide → NF_ACCEPT", ->
      payload_raw = ""
      assert.equals 1, invoke!

    it "en-tête IP illisible → NF_ACCEPT", ->
      payload_raw = "\xff\x00\x00\x00" .. string.rep("\0", 40)
      assert.equals 1, invoke!

    it "TCP illisible (segment trop court) → NF_ACCEPT", ->
      payload_raw = ipv4_packet 6, string.rep("\0", 10)
      assert.equals 1, invoke!

    it "TCP header_len invalide → NF_ACCEPT", ->
      -- header_len = 0x10 (data offset 4 mots = 16 < 20) : ipparse renvoie nil.
      payload_raw = ipv4_tcp "x", header_len: 0x10
      assert.equals 1, invoke!

    it "TCP data_off au-delà du buffer → NF_ACCEPT", ->
      -- 60 octets d'en-tête TCP (40 d'options) sans payload : data_off = 81
      -- pour un buffer de 80 octets.
      payload_raw = ipv4_tcp "", header_len: 0xF0, tcp_options: 40
      assert.equals 1, invoke!

    it "UDP illisible (segment trop court) → NF_ACCEPT", ->
      payload_raw = ipv4_packet 17, string.rep("\0", 4)
      assert.equals 1, invoke!

  describe "ClientHello TLS (TCP)", ->
    it "SNI extrait + verdict allow → sets nft, événement allow, NF_ACCEPT", ->
      decide_result = { verdict: true, reason: "Allowed by rule: lan", rule_id: "r_lan" }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "example.com"
      assert.equals 1, invoke!
      -- Une commande ip4 puis une mac4, avec le timeout SNI (concaténées
      -- en un seul appel nft par apply_nft_allow).
      assert.equals 1, #nft_cmds
      lines = [l for l in nft_cmds[1]\gmatch "[^\n]+"]
      assert.equals 2, #lines
      assert.is_truthy lines[1]\match "^ip4 192%.0%.2%.10 93%.184%.216%.34 r_lan"
      assert.is_truthy lines[2]\match "^mac4 aa:bb:cc:dd:ee:ff 93%.184%.216%.34 r_lan"
      assert.equals 1, #events_out
      fields = split_tabs events_out[1]
      assert.equals "allow", fields[2]
      assert.equals "example.com", fields[3]
      assert.equals "aa:bb:cc:dd:ee:ff", fields[4]
      assert.equals "192.0.2.10", fields[5]
      assert.equals "93.184.216.34", fields[6]
      assert.equals "7", fields[7]
      assert.equals "ipv4", fields[9]
      assert.equals "r_lan", fields[11]
      -- La requête filtre porte le SNI normalisé et l'utilisateur de session.
      req = package.loaded["_filtered_stub"].last_req
      assert.equals "example.com", req.domain
      assert.equals "alice", req.user
      assert.equals 7, req.vlan

    it "mode non strict + verdict block → skip (NF_ACCEPT), pas d'événement block", ->
      sni_cfg.mode = "integral"
      w.run 0, 42
      decide_result = { verdict: false, reason: "blocked", rule_id: "r_blk" }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "ads.example"
      assert.equals 1, invoke!
      assert.equals 0, #events_out
      assert.equals 0, #mark_calls

    it "mode strict + verdict block → mark + événement block + VERDICT_DONE", ->
      decide_result = { verdict: false, reason: "blocked", rule_id: "r_blk" }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "ads.example"
      assert.equals -1, invoke!
      assert.equals 1, #mark_calls
      assert.equals 0x02000000, mark_calls[1].mark
      fields = split_tabs events_out[1]
      assert.equals "block", fields[2]
      assert.equals "ads.example", fields[3]
      assert.equals "blocked", fields[10]
      assert.equals "r_blk", fields[11]

    it "échec de pose de mark → NF_DROP", ->
      mark_rc = -1
      decide_result = { verdict: false, reason: "blocked", rule_id: "r_blk" }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "ads.example"
      assert.equals 0, invoke!

    it "verdict dnsonly strict → blocage routé vers worker_reject", ->
      decide_result = { verdict: "dnsonly", reason: "DNS only", rule_id: "r_dns" }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "dns.example"
      assert.equals -1, invoke!
      assert.equals 1, #mark_calls

    it "redirect déjà sur la bonne IP (CNAME) → allow", ->
      decide_result = {
        verdict: true, redirects_destination: true
        cname_target: "forcesafesearch.example", reason: "redirect", rule_id: "r_safe"
      }
      w.set_validator_state {
        cname_mod: {
          pick_resolver_ip: -> "1.1.1.1"
          resolve_target_rrs: -> { a: { s2ip "93.184.216.34" }, aaaa: {} }
        }
        filter_cfg: {}
      }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "safe.example"
      assert.equals 1, invoke!
      assert.equals 1, #nft_cmds
      assert.is_truthy nft_cmds[1]\match "^ip4"
      assert.equals "allow", (split_tabs events_out[1])[2]

    it "redirect vers une autre IP en strict → blocage (mauvaise IP)", ->
      decide_result = {
        verdict: true, redirects_destination: true
        cname_target: "forcesafesearch.example", reason: "redirect", rule_id: "r_safe"
      }
      w.set_validator_state {
        cname_mod: {
          pick_resolver_ip: -> "1.1.1.1"
          resolve_target_rrs: -> { a: { s2ip "1.2.3.4" }, aaaa: {} }
        }
        filter_cfg: {}
      }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "safe.example"
      assert.equals -1, invoke!
      fields = split_tabs events_out[1]
      assert.equals "block", fields[2]
      assert.equals "sni_redirect_wrong_ip", fields[10]

    it "redirect dont la cible n'est pas résolue → raison unresolved", ->
      decide_result = {
        verdict: true, redirects_destination: true
        cname_target: "unresolved.example", reason: "redirect", rule_id: "r_safe"
      }
      w.set_validator_state {
        cname_mod: { pick_resolver_ip: -> "1.1.1.1", resolve_target_rrs: -> nil }
        filter_cfg: {}
      }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "safe.example"
      assert.equals -1, invoke!
      assert.equals "sni_redirect_target_unresolved", (split_tabs events_out[1])[10]

    it "validate bloqué par le second avis → blocage", ->
      decide_result = {
        verdict: true, allow_modifiers: { validate: true }
        reason: "Validated", rule_id: "r_val"
      }
      w.set_validator_state {
        validator_mod: { query_verdict: -> true, "malware" }
        second_opinion_cfg: { resolvers: { "1.1.1.1" } }
      }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "bad.example"
      assert.equals -1, invoke!
      assert.equals "malware", (split_tabs events_out[1])[10]

    it "validate non bloqué → allow (sets nft)", ->
      decide_result = {
        verdict: true, allow_modifiers: { validate: true }
        reason: "Validated", rule_id: "r_val"
      }
      w.set_validator_state {
        validator_mod: { query_verdict: -> false, nil }
        second_opinion_cfg: { resolvers: { "1.1.1.1" } }
      }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "ok.example"
      assert.equals 1, invoke!
      assert.equals 1, #nft_cmds

    it "filtre indisponible (pas de decide_meta) → fail-open NF_ACCEPT", ->
      -- Mutation de la table capturée par run() : pas de rechargement du
      -- module (évite de multiplier les instances FFI dans un même process).
      stub = package.loaded["filter"]
      stub.decide_meta = nil
      w.run 0, 42
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "open.example"
      assert.equals 1, invoke!
      assert.equals 0, #nft_cmds

    it "exception de decide_meta → fail-open NF_ACCEPT", ->
      decide_throws = true
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "boom.example"
      assert.equals 1, invoke!

    it "protocols=tcp-only laisse passer le QUIC hors périmètre", ->
      sni_cfg.protocols = "tcp-only"
      w.run 0, 42
      payload_raw = ipv4_udp string.rep("\x40", 32)
      assert.equals 1, invoke!

  describe "absence de SNI", ->
    it "ClientHello sans extension SNI en strict → block no_sni + routage", ->
      decide_result = { verdict: true, rule_id: "r" }
      payload_raw = ipv4_tcp build_client_hello make_supported_versions_ext!
      assert.equals -1, invoke!
      fields = split_tabs events_out[1]
      assert.equals "block", fields[2]
      assert.equals "no_sni_in_extensions", fields[10]
      assert.equals "strict-443/no_sni", fields[11]

    it "port mail + strict sans SNI → warn, NF_ACCEPT", ->
      ch = build_client_hello make_supported_versions_ext!
      payload_raw = ipv4_tcp ch, dport: 465
      assert.equals 1, invoke!
      fields = split_tabs events_out[1]
      assert.equals "warn", fields[2]
      assert.equals "mail_ssl/no_sni", fields[11]

    it "port mail 587/993/995 classés et avertis sans blocage", ->
      ch = build_client_hello make_supported_versions_ext!
      for dport in *{ 587, 993, 995 }
        events_out = {}
        payload_raw = ipv4_tcp ch, :dport
        assert.equals 1, invoke!
        assert.equals "warn", (split_tabs events_out[1])[2]

    it "mode non strict sans SNI → NF_ACCEPT sans événement", ->
      sni_cfg.mode = "integral"
      w.run 0, 42
      payload_raw = ipv4_tcp build_client_hello make_supported_versions_ext!
      assert.equals 1, invoke!
      assert.equals 0, #events_out

    it "record non-TLS (0x17) → NF_ACCEPT", ->
      payload_raw = ipv4_tcp "\x17\x03\x03\x00\x05hello"
      assert.equals 1, invoke!

    it "Handshake non-ClientHello → NF_ACCEPT", ->
      payload_raw = ipv4_tcp build_client_hello (make_sni_ext "x.example"), hs_type: 0x02
      assert.equals 1, invoke!

    it "ClientHello fragmenté (record incomplet) → NF_ACCEPT en attendant", ->
      record = build_client_hello make_sni_ext "frag.example"
      payload_raw = ipv4_tcp record\sub(1, math.floor #record / 2)
      assert.equals 1, invoke!

  describe "QUIC (UDP)", ->
    -- Le déchiffrement QUIC Initial dépend d'un backend crypto natif
    -- (wolfssl/mbedtls/openssl) absent du runner unitaire : les sessions sont
    -- donc simulées ici. L'extraction réelle est couverte par le groupe G14
    -- de `make test-e2e` (fixture tests/e2e/fixtures/quic_initial.bin).
    sni_session = (sni) -> { push: (-> true), sni: -> sni }

    it "session QUIC avec SNI + verdict block strict → drop direct + événement", ->
      sess = package.loaded["ipparse.l7.quic.session"]
      orig_new = sess.new
      sess.new = -> sni_session "quic.example"
      decide_result = { verdict: false, reason: "blocked", rule_id: "r_q" }
      payload_raw = ipv4_udp QUIC_INITIAL, dport: 443
      ok, ret = pcall invoke
      sess.new = orig_new
      assert.is_true ok
      assert.equals 0, ret   -- UDP → NF_DROP direct (les clients ignorent ICMP)
      fields = split_tabs events_out[1]
      assert.equals "block", fields[2]
      assert.equals "quic.example", fields[3]

    it "session QUIC avec SNI + allow → sets ip4/mac4 et événement allow", ->
      sess = package.loaded["ipparse.l7.quic.session"]
      orig_new = sess.new
      sess.new = -> sni_session "quic.example"
      decide_result = { verdict: true, reason: "ok", rule_id: "r_q" }
      payload_raw = ipv4_udp QUIC_INITIAL, dport: 443
      ok, ret = pcall invoke
      sess.new = orig_new
      assert.is_true ok
      assert.equals 1, ret
      assert.equals 1, #nft_cmds
      assert.is_truthy nft_cmds[1]\match "^ip4 192%.0%.2%.10 93%.184%.216%.34 r_q"
      assert.equals "allow", (split_tabs events_out[1])[2]

    it "payload QUIC trop court → chemin no-SNI strict", ->
      payload_raw = ipv4_udp "\x00\x01", dport: 443
      assert.equals 0, invoke!
      assert.equals "short_payload", (split_tabs events_out[1])[10]

    it "échec d'init de session QUIC → warn quic_parse_failed + no-SNI", ->
      sess = package.loaded["ipparse.l7.quic.session"]
      orig_new = sess.new
      sess.new = -> error "session boom"
      payload_raw = ipv4_udp QUIC_INITIAL, dport: 443
      ok, ret = pcall invoke
      sess.new = orig_new
      assert.is_true ok
      assert.equals 0, ret
      assert.is_truthy (split_tabs events_out[1])[10]\match "^quic_session_init_failed"

    it "push de session QUIC en échec → drop, no-SNI", ->
      sess = package.loaded["ipparse.l7.quic.session"]
      orig_new = sess.new
      sess.new = -> { push: push_fail, sni: -> nil }
      payload_raw = ipv4_udp QUIC_INITIAL, dport: 443
      ok, ret = pcall invoke
      sess.new = orig_new
      assert.is_true ok
      assert.equals 0, ret
      assert.is_truthy (split_tabs events_out[1])[10]\match "^quic_push_failed"

    it "session QUIC sans SNI → no_sni_in_crypto", ->
      sess = package.loaded["ipparse.l7.quic.session"]
      orig_new = sess.new
      sess.new = -> { push: (-> true), sni: (-> nil) }
      payload_raw = ipv4_udp QUIC_INITIAL, dport: 443
      ok, ret = pcall invoke
      sess.new = orig_new
      assert.is_true ok, tostring ret
      assert.equals 0, ret
      assert.equals "quic_no_sni_in_crypto", (split_tabs events_out[1])[10]

    it "plafond de sessions atteint → prune avant d'ouvrir une nouvelle session", ->
      w.reset_quic_sessions!
      now = os.time!
      for i = 1, 4096
        w.seed_quic_session "k#{i}", now
      assert.equals 4096, w.quic_session_count!
      sess = package.loaded["ipparse.l7.quic.session"]
      orig_new = sess.new
      sess.new = -> sni_session "quic.example"
      -- Entrée très ancienne : prune_quic_sessions (TTL 30 s) l'évince.
      w.seed_quic_session "stale", now - 1000
      payload_raw = ipv4_udp QUIC_INITIAL, dport: 443
      ok = pcall invoke
      sess.new = orig_new
      assert.is_true ok
      assert.is_true w.quic_session_count! <= 4096

  describe "échec nft", ->
    it "fail-closed (défaut) → blocage routé", ->
      nft_ok = false
      nft_err = "nft broken"
      decide_result = { verdict: true, reason: "ok", rule_id: "r1" }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "nft.example"
      assert.equals -1, invoke!
      fields = split_tabs events_out[1]
      assert.equals "block", fields[2]
      assert.equals "nft broken", fields[10]

    it "fail-open → NF_ACCEPT malgré l'échec nft", ->
      sni_cfg.nft_failure_policy = "fail-open"
      w.run 0, 42
      nft_ok = false
      decide_result = { verdict: true, reason: "ok", rule_id: "r1" }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "nft.example"
      assert.equals 1, invoke!
      assert.equals 1, #nft_cmds
      assert.equals "allow", (split_tabs events_out[1])[2]

    it "commande impossible à construire → nft_cmd_build_failed", ->
      package.loaded["nft_queue"] = { cmd_for: -> nil }
      w.reset_nft_modules!
      decide_result = { verdict: true, reason: "ok", rule_id: "r1" }
      payload_raw = ipv4_tcp build_client_hello make_sni_ext "nft.example"
      assert.equals -1, invoke!
      assert.equals "nft_cmd_build_failed", (split_tabs events_out[1])[10]

    it "module nft_queue introuvable → nft_insert_failed", ->
      w.reset_nft_modules!
      orig = _G.require
      _G.require = (name) ->
        error "introuvable" if name == "nft_queue"
        orig name
      ok = pcall ->
        payload_raw = ipv4_tcp build_client_hello make_sni_ext "nft.example"
        invoke!
      _G.require = orig
      assert.is_true ok

  describe "run()", ->
    it "charge le filtre et arme run_queue sur handle_sni_packet", ->
      w.run "7", nil
      assert.is_not_nil run_cb
      assert.equals 1, run_cb nil, nil, 1   -- L2 nil → NF_ACCEPT

    it "propage les données de filtre fournies par main", ->
      fdata = {
        rules: { r1: true }
        auth_cfg_cache: { a: 1 }
        sni_cfg_cache: { b: 2 }
        decision_cfg: { c: 3 }
      }
      w.run 0, nil, fdata
      stub = package.loaded["filter"]
      assert.same fdata.rules, stub.rules
      assert.same fdata.auth_cfg_cache, stub.auth_cfg_cache
      assert.same fdata.sni_cfg_cache, stub.sni_cfg_cache
      assert.same fdata.decision_cfg, stub.decision_cfg

    it "politique désactivée → callback NF_ACCEPT constant", ->
      sni_cfg = { enabled: false }
      w.run 0, nil
      assert.is_not_nil run_cb
      assert.equals 1, run_cb nil, nil, 1

    it "filtre sans get_auth_cfg/get_sni_cfg → défauts conservés", ->
      stub = package.loaded["filter"]
      stub.get_auth_cfg = nil
      stub.get_sni_cfg = nil
      w.run 0, nil
      assert.is_not_nil run_cb

    it "échec de require filter → politique par défaut et warn", ->
      orig = _G.require
      _G.require = (name) ->
        error "filter boom" if name == "filter"
        orig name
      pcall -> w.run 0, nil
      _G.require = orig

  describe "variantes de transport et d'état", ->
    it "ClientHello IPv6 → af ipv6 et sets ip6/mac6", ->
      decide_result = { verdict: true, reason: "ok", rule_id: "r6" }
      payload_raw = ipv6_tcp build_client_hello make_sni_ext "v6.example"
      assert.equals 1, invoke!
      assert.equals 1, #nft_cmds
      lines = [l for l in nft_cmds[1]\gmatch "[^\n]+"]
      assert.equals 2, #lines
      assert.is_truthy lines[1]\match "^ip6 2001:db8::1 2001:db8::2 r6"
      fields = split_tabs events_out[1]
      assert.equals "v6.example", fields[3]
      assert.equals "ipv6", fields[9]

    it "protocole hors périmètre avec SNI extrait → skip avant décision d'action", ->
      sni_cfg.protocols = "tcp-only"
      w.run 0, 42
      sess = package.loaded["ipparse.l7.quic.session"]
      orig_new = sess.new
      sess.new = -> { push: (-> true), sni: (-> "quic.example") }
      decide_result = { verdict: true, reason: "ok", rule_id: "r_q" }
      payload_raw = ipv4_udp QUIC_INITIAL, dport: 443
      ok, ret = pcall invoke
      sess.new = orig_new
      assert.is_true ok
      assert.equals 1, ret
      assert.equals 0, #nft_cmds
      -- La décision filtre est bien évaluée, mais l'action n'est pas appliquée.
      assert.is_not_nil package.loaded["_filtered_stub"].last_req

    it "prune_quic_sessions sans argument utilise l'horloge courante", ->
      w.reset_quic_sessions!
      w.seed_quic_session "stale", os.time! - 1000
      w.seed_quic_session "fresh", os.time!
      assert.equals 1, w.prune_quic_sessions!
      assert.equals 1, w.quic_session_count!

    it "réutilise une session QUIC déjà ouverte pour la même clé", ->
      sess = package.loaded["ipparse.l7.quic.session"]
      orig_new = sess.new
      created = 0
      sess.new = ->
        created += 1
        { push: (-> true), sni: (-> nil) }
      w.reset_quic_sessions!
      w.extract_sni_from_quic QUIC_INITIAL, "same-key"
      w.extract_sni_from_quic QUIC_INITIAL, "same-key"
      sess.new = orig_new
      -- Une seule création pour deux paquets du même flux.
      assert.equals 1, created

    it "set_validator_state sans argument conserve l'état courant", ->
      w.set_validator_state!
      assert.is_false w.validate_sni "keep.test", true

    it "validateur introuvable → fail-open avec raison dédiée", ->
      orig = _G.require
      _G.require = (name) ->
        error "absent" if name == "doh.validator"
        orig name
      w.set_validator_state {
        validator_mod: false
        second_opinion_cfg: { resolvers: { "1.1.1.1" } }
      }
      blocked, reason = w.validate_sni "novalidator.test", true
      _G.require = orig
      assert.is_false blocked
      assert.equals "validator_require_failed", reason

    it "module cname introuvable → redirect non résolu", ->
      orig = _G.require
      _G.require = (name) ->
        error "absent" if name == "filter.actions.cname"
        orig name
      w.set_validator_state { cname_mod: false, filter_cfg: {} }
      matched, resolved = w.dst_matches_cname "target.test", "1.2.3.4", 4
      _G.require = orig
      assert.is_false matched
      assert.is_false resolved

    it "dst_matches_cname interroge les AAAA pour une cible IPv6", ->
      w.set_validator_state {
        cname_mod: {
          pick_resolver_ip: -> "1.1.1.1"
          resolve_target_rrs: -> { aaaa: { s2ip "2001:db8::5" }, a: {} }
        }
        filter_cfg: {}
      }
      matched, resolved = w.dst_matches_cname "target.test", "2001:db8::5", 6
      assert.is_true matched
      assert.is_true resolved
      -- Liste AAAA vide → non matché mais cible résolue.
      w.set_validator_state {
        cname_mod: {
          pick_resolver_ip: -> "1.1.1.1"
          resolve_target_rrs: -> { aaaa: {}, a: {} }
        }
        filter_cfg: {}
      }
      matched, resolved = w.dst_matches_cname "target.test", "2001:db8::5", 6
      assert.is_false matched
      assert.is_true resolved

  describe "helpers", ->
    it "format_mac : inconnue si donnée absente/mauvaise taille", ->
      assert.equals "unknown", w.format_mac nil
      assert.equals "unknown", w.format_mac "abc"
      assert.equals "aa:bb:cc:dd:ee:ff", w.format_mac "\170\187\204\221\238\255"

    it "format_ip : inconnue sur version/taille invalides", ->
      assert.equals "unknown", w.format_ip 4, nil
      assert.equals "unknown", w.format_ip 5, "\1\2\3\4"
      assert.equals "unknown", w.format_ip 4, "\1\2"
      assert.equals "192.0.2.10", w.format_ip 4, s2ip "192.0.2.10"
      assert.equals "2001:db8::1", w.format_ip 6, s2ip "2001:db8::1"

    it "is_mail_ssl_port ne reconnaît que les quatre ports mail", ->
      for p in *{ 465, 587, 993, 995 }
        assert.is_true w.is_mail_ssl_port p
      for p in *{ 80, 443, 5060, 8443 }
        assert.is_false w.is_mail_ssl_port p

    it "tls_version_name couvre 1.0 à 1.3, inconnue et nil", ->
      assert.is_nil w.tls_version_name nil
      assert.equals "TLS1.0", w.tls_version_name 0x0301
      assert.equals "TLS1.1", w.tls_version_name 0x0302
      assert.equals "TLS1.2", w.tls_version_name 0x0303
      assert.equals "TLS1.3", w.tls_version_name 0x0304
      assert.equals "0x0300", w.tls_version_name 0x0300

    it "extract_supported_versions : liste, sélection serveur, données invalides", ->
      assert.is_nil w.extract_supported_versions nil
      assert.is_nil w.extract_supported_versions "\x03"
      assert.equals "TLS1.3", w.extract_supported_versions "\x04\x03\x04\x03\x03"
      assert.equals "TLS1.3", w.extract_supported_versions "\x03\x04"
      -- liste déclarée plus longue que les données → parse en échec → nil
      assert.is_nil w.extract_supported_versions "\x08\x03\x04"

    it "write_sni_event sans fd ne fait rien, avec fd écrit une ligne TSV", ->
      package.loaded["worker_tls"] = nil
      w2 = require "worker_tls"
      assert.is_nil w2.write_sni_event "allow", { sni: "x" }
      assert.equals 0, #events_out
      w.run 0, 42
      w.write_sni_event "allow", {
        sni: "a.example", mac_src: "aa:bb", src_ip: "1.2.3.4", dst_ip: "5.6.7.8"
        vlan: 3, user: "bob", af: "ipv4", reason: "ok", rule: "r1"
      }
      f = split_tabs events_out[1]
      assert.equals 11, #f
      assert.equals "allow", f[2]
      assert.equals "a.example", f[3]
      assert.equals "bob", f[8]
      assert.equals "r1", f[11]

  describe "repli tolérant TLS (extract_sni_from_tls)", ->
    full = -> build_client_hello (make_supported_versions_ext! .. make_sni_ext "fallback.example")

    it "retrouve le SNI quand le parseur strict échoue (longueur d'extensions surdéclarée)", ->
      exts = make_supported_versions_ext! .. make_sni_ext "fallback.example"
      payload = build_client_hello exts, ext_len_override: #exts + 64
      host, reason, meta = w.extract_sni_from_tls payload
      assert.equals "fallback.example", host
      assert.is_nil reason
      assert.equals "fallback", meta.tls_parser_path
      assert.equals "TLS1.3", meta.tls_supported_version

    it "couvre toutes les raisons de troncature du repli", ->
      record = (build_client_hello make_supported_versions_ext!) .. ""
      seen = {}
      for cut = 9, #record - 1
        _, reason = w.extract_sni_from_tls record\sub(1, cut)
        seen[reason] = true if reason
      for expected in *{
        "fallback_short_random", "fallback_no_session_id_len"
        "fallback_short_cipher_len", "fallback_short_cipher_suites"
        "fallback_short_compression_len", "fallback_short_compression"
        "fallback_short_extensions_len"
      }
        assert.is_true seen[expected], "raison absente : #{expected}"

    it "extension SNI trop courte dans le repli → fallback_short_sni_ext", ->
      short_ext = table.concat { u16(0x0000), u16(3), "abc" }
      payload = build_client_hello short_ext, ext_len_override: #short_ext + 32
      _, reason = w.extract_sni_from_tls payload
      assert.equals "fallback_short_sni_ext", reason

    it "extension SNI mal formée dans le repli → no_sni_in_extensions", ->
      -- name_type ≠ 0 : le repli rejette l'entrée et poursuit sans SNI.
      bad = table.concat {
        u16 0x0000
        u16 8
        u16 5
        string.char 0x01           -- name_type = 1 (non host_name)
        u16 2
        "ab"
      }
      payload = build_client_hello bad, ext_len_override: #bad + 32
      host, reason = w.extract_sni_from_tls payload
      assert.is_nil host
      assert.equals "no_sni_in_extensions", reason

  describe "extract_sni_from_quic (erreurs de session)", ->
    it "en-tête QUIC illisible → quic_header_parse_failed", ->
      host, reason, meta = w.extract_sni_from_quic string.rep("\xff", 40)
      assert.is_nil host
      assert.equals "quic_header_parse_failed", reason
      assert.equals "none", meta.quic_parser_path

    it "paquet QUIC non-Initial → quic_not_initial", ->
      -- En-tête long (0x80) de type Handshake (bits 0x30 = 0x10) → type 0x20.
      host, reason = w.extract_sni_from_quic "\xf0" .. string.rep("\0", 40)
      assert.is_nil host
      assert.is_truthy reason\match "^quic_"
