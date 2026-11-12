-- tests/unit/worker_questions_spec.moon
-- T1 : chemin de décision du worker question.
-- Couvre list_from_condition_reason, write_event (format TSV) et handle_question
-- (verdict rendu + message IPC émis), avec des stubs locaux pour les dépendances
-- FFI NFQUEUE / filter / sockets, restaurés en teardown. Le parsing L3/L4/L7 est
-- déjà couvert par tests/unit/packet_utils_spec.moon (parse_dns_packet).

ffi = require "ffi"
sp = require("ipparse.lib.pack_compat").pack
{ :s2ip } = require "ipparse.l3.ip"
ipc = require "ipc"

-- Charge d'abord lib.socket : ses cdef (dont __errno_location) sont déclarés en
-- un bloc ; les déclarer après coup échouerait en redéfinition.
pcall require, "lib.socket"

for decl in *{
  "int  pipe(int pipefd[2]);"
  "int  close(int fd);"
  "long read(int fd, void *buf, unsigned long count);"
  "long write(int fd, const void *buf, unsigned long count);"
  "int* __errno_location(void);"
}
  pcall ffi.cdef, decl

STUB_KEYS = {
  "ffi_defs", "worker_questions", "filter", "nfq/ethernet", "nfq_loop"
  "forge_dns", "captive_ips", "bridge_raw", "dup_query", "raw_send", "metrics"
}
saved = {}

save_all = ->
  saved[k] = package.loaded[k] for k in *STUB_KEYS

restore_all = ->
  for k in *STUB_KEYS
    package.loaded[k] = saved[k]

make_pipe = ->
  fds = ffi.new "int[2]"
  assert.equals 0, ffi.C.pipe fds
  fds[0], fds[1]

read_fd = (fd) ->
  buf = ffi.new "char[4096]"
  n = tonumber ffi.C.read fd, buf, 4096
  return "" unless n and n > 0
  ffi.string buf, n

-- Query DNS (id 0xabcd, qr=0, question example.com A) et sa variante réponse.
DNS_QUERY = "\xab\xcd\1\0\0\1\0\0\0\0\0\0\7example\3com\0\0\1\0\1"
DNS_REPLY = "\xab\xcd\x81\x80\0\1\0\1\0\0\0\0\7example\3com\0\0\1\0\1" ..
  "\192\012\0\1\0\1\0\0\0\60\0\4\1\2\3\4"

ipv4_udp = (dns) ->
  udp_len = 8 + #dns
  total   = 20 + udp_len
  hdr = sp ">B B H H H B B H", 0x45, 0, total, 0x1234, 0, 64, 17, 0
  hdr ..= s2ip("192.0.2.10") .. s2ip("1.1.1.1")
  hdr .. sp(">H H H H", 5353, 53, udp_len, 0) .. dns

split_tabs = (line) ->
  out = {}
  for f in (line\gsub("\n$", ""))\gmatch "[^\t]+"
    out[#out + 1] = f
  out

ipv6_udp = (dns) ->
  udp_len = 8 + #dns
  hdr = string.char(0x60, 0, 0, 0) .. sp(">H B B", udp_len, 17, 64)
  hdr ..= s2ip("2001:db8::1") .. s2ip("2001:db8::53")
  hdr .. sp(">H H H H", 5353, 53, udp_len, 0) .. dns

describe "worker_questions", ->

  decision = nil
  payload = ""
  -- Tampon stable (cf. worker_auth_queue_spec) : le pointeur rendu par
  -- nfq_get_payload doit rester valide après le retour du stub.
  payload_buf = ffi.new "uint8_t[?]", 65536
  wq = nil
  ev_r = nil
  ev_w = nil
  pipe_r = nil
  pipe_w = nil
  -- Captures du câblage run_queue → metrics (P2.3) : les options passées à
  -- run_queue et l'ordre des appels au module metrics.
  captured_opts = nil
  metrics_calls = {}

  before_each ->
    save_all!
    decision = nil
    payload  = ""
    captured_opts = nil
    metrics_calls = {}

    ev_r, ev_w     = make_pipe!
    pipe_r, pipe_w = make_pipe!

    -- Stubs locaux : restaurés en after_each (cf. save_all/restore_all).
    package.loaded["ffi_defs"] = {
      :ffi
      libc: ffi.C
      libnfq: {
        nfq_get_payload: (nfad, out) ->
          ffi.copy payload_buf, payload, #payload
          out[0] = ffi.cast "unsigned char*", payload_buf
          #payload
      }
    }
    package.loaded["filter"] = {
      get_auth_cfg: -> {}
      decide_meta: (req) -> decision
    }
    package.loaded["nfq/ethernet"] = {
      get_l2: -> {
        mac_src:    "aa:bb:cc:dd:ee:ff"
        mac_raw:    "\170\187\204\221\238\255"
        in_ifindex: 5
        vlan:       nil
      }
    }
    package.loaded["nfq_loop"] = {
      NF_ACCEPT: 1
      NF_DROP: 0
      run_queue: (queue, cb, opts) ->
        captured_opts = opts
        nil
    }
    package.loaded["forge_dns"] = {}
    package.loaded["captive_ips"] = {
      detect: (-> nil, nil)
      domain_from_url: -> nil
    }
    package.loaded["bridge_raw"] = {}
    package.loaded["dup_query"] = { pick_resolver: -> nil }
    package.loaded["raw_send"] = { routable: -> false }
    package.loaded["metrics"] = {
      init: ->
        metrics_calls[#metrics_calls + 1] = "init"
        nil
      record_verdict: ->
        metrics_calls[#metrics_calls + 1] = "record_verdict"
        nil
      write_now: ->
        metrics_calls[#metrics_calls + 1] = "write_now"
        nil
      flush_if_due: ->
        metrics_calls[#metrics_calls + 1] = "flush_if_due"
        true
    }

    package.loaded["worker_questions"] = nil
    wq = require "worker_questions"
    wq.run 0, pipe_w, nil, ev_w, nil

  after_each ->
    for fd in *{ ev_r, ev_w, pipe_r, pipe_w }
      ffi.C.close fd if fd
    restore_all!

  invoke = (raw) ->
    payload = raw
    wq.handle_question nil, nil, 1

  -- ── Câblage métriques (P2.3) ─────────────────────────────────────────────
  -- Depuis la suppression de `maybe_flush`, la seule écriture périodique des
  -- instantanés est `run_queue` → `on_idle = metrics.flush_if_due`. Si ces
  -- options disparaissaient (refactoring, `metrics_on` mal évalué), il ne
  -- resterait que write_now au démarrage/à l'arrêt et /admin/metrics cesserait
  -- d'être rafraîchie sous trafic, silencieusement.
  describe "câblage métriques → run_queue", ->
    it "passe on_idle = metrics.flush_if_due et idle_ms > 0 quand les métriques sont actives", ->
      assert.is_not_nil captured_opts
      metrics_mod = assert package.loaded["metrics"]
      assert.is_not_nil metrics_mod.flush_if_due
      assert.equals metrics_mod.flush_if_due, captured_opts.on_idle
      assert.is_number captured_opts.idle_ms
      assert.is_true captured_opts.idle_ms > 0

    it "n'appelle ni write_now ni flush_if_due dans handle_question (aucune horloge par paquet)", ->
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      before = #metrics_calls
      invoke ipv4_udp DNS_QUERY
      added = {}
      for i = before + 1, #metrics_calls
        added[#added + 1] = metrics_calls[i]
      assert.same { "record_verdict" }, added

  -- ── list_from_condition_reason (pur) ──────────────────────────────────────
  describe "list_from_condition_reason", ->
    it "extrait le nom de liste du motif to_domainlist", ->
      assert.equals "toulouse/malware",
        wq.list_from_condition_reason "Domain matched in list 'toulouse/malware'"

    it "retourne nil pour un motif non reconnu", ->
      assert.is_nil wq.list_from_condition_reason "Allowed by rule: users"
      assert.is_nil wq.list_from_condition_reason nil
      assert.is_nil wq.list_from_condition_reason 42

    it "exige un nom non vide et la fin de chaîne", ->
      assert.is_nil wq.list_from_condition_reason "Domain matched in list ''"
      assert.is_nil wq.list_from_condition_reason "Domain matched in list 'x' extra"

  -- ── write_event (format TSV) ──────────────────────────────────────────────
  describe "write_event", ->
    it "écrit une ligne TSV allow avec '-' pour les champs vides", ->
      wq.write_event {
        qname: "example.com", mac_src: "aa:bb:cc:dd:ee:ff"
        src_ip: "192.0.2.10", dst_ip: "1.1.1.1", vlan: 8
        user: nil, af: "ipv4", reason: "Allowed by rule: x", rule: "r1"
      }, true
      line = read_fd ev_r
      assert.is_true line\sub(-1) == "\n"
      fields = split_tabs line
      assert.equals 11, #fields
      assert.is_not_nil fields[1]\match "^%d+$"
      assert.equals "allow", fields[2]
      assert.equals "example.com", fields[3]
      assert.equals "aa:bb:cc:dd:ee:ff", fields[4]
      assert.equals "192.0.2.10", fields[5]
      assert.equals "1.1.1.1", fields[6]
      assert.equals "8", fields[7]
      assert.equals "-", fields[8]
      assert.equals "ipv4", fields[9]
      assert.equals "Allowed by rule: x", fields[10]
      assert.equals "r1", fields[11]

    it "marque block quand la décision est refusée", ->
      wq.write_event { qname: "malware.example", af: "ipv4" }, false
      fields = split_tabs read_fd ev_r
      assert.equals "block", fields[2]
      assert.equals "malware.example", fields[3]

  -- ── handle_question : décisions et messages IPC ───────────────────────────
  describe "handle_question", ->
    it "autorise une question UDP/IPv4 : write_msg et événement allow", ->
      decision = {
        verdict: true
        reason: "Allowed by test rule"
        rule_id: "r_allow"
        timeout: "2m"
        response_rule_ids: { "r_allow" }
      }
      rc = invoke ipv4_udp DNS_QUERY
      assert.equals 1, rc

      msg = ipc.decode_msg read_fd pipe_r
      assert.equals ipc.MSG_IPV4, msg.msg_type
      assert.equals 0xabcd, msg.txid
      assert.equals "192.0.2.10", msg.ip_str
      assert.equals 5353, msg.src_port
      assert.equals "1.1.1.1", msg.resolver_ip_str
      assert.equals "aa:bb:cc:dd:ee:ff", msg.mac_str
      assert.equals "Allowed by test rule", msg.reason
      assert.equals "r_allow", msg.rule_id
      assert.equals "2m", msg.timeout
      assert.same { "r_allow" }, msg.response_rule_ids
      assert.is_false msg.refused

      fields = split_tabs read_fd ev_r
      assert.equals "allow", fields[2]
      assert.equals "example.com", fields[3]
      assert.equals "192.0.2.10", fields[5]
      assert.equals "1.1.1.1", fields[6]
      assert.equals "-", fields[7]     -- vlan nil
      assert.equals "ipv4", fields[9]
      assert.equals "Allowed by test rule", fields[10]
      assert.equals "r_allow", fields[11]

    it "autorise une question UDP/IPv6 : message IPC IPv6", ->
      decision = { verdict: true, reason: "ok", rule_id: "r6" }
      rc = invoke ipv6_udp DNS_QUERY
      assert.equals 1, rc

      msg = ipc.decode_msg read_fd pipe_r
      assert.equals ipc.MSG_IPV6, msg.msg_type
      assert.equals "2001:db8::1", msg.ip_str
      assert.equals "2001:db8::53", msg.resolver_ip_str
      assert.equals "r6", msg.rule_id

    it "refuse une question : write_refused_msg, question acceptée (réponse filtrée côté response)", ->
      decision = {
        verdict: false
        reason: "Blocked by test rule"
        rule_id: "r_block"
        timeout: "30s"
        response_rule_ids: { "r_block" }
      }
      rc = invoke ipv4_udp DNS_QUERY
      assert.equals 1, rc

      msg = ipc.decode_msg read_fd pipe_r
      assert.equals ipc.MSG_IPV4_REFUSED, msg.msg_type
      assert.is_true msg.refused
      assert.equals "Blocked by test rule", msg.reason
      assert.equals "r_block", msg.rule_id

      fields = split_tabs read_fd ev_r
      assert.equals "block", fields[2]

    it "échec d'écriture IPC → NF_DROP (fail-closed)", ->
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      -- fd invalide : ipc.write_with_retry échoue (EBADF) sans SIGPIPE.
      wq.run 0, -1, nil, ev_w, nil
      rc = invoke ipv4_udp DNS_QUERY
      assert.equals 0, rc

    it "laisse passer une réponse DNS (qr=1) sans message IPC", ->
      rc = invoke ipv4_udp DNS_REPLY
      assert.equals 1, rc

    it "rejette un paquet tronqué (parse_failed) sans message IPC", ->
      rc = invoke "\x45\x00"
      assert.equals 0, rc

    it "payload vide ou d'une longueur nulle → NF_DROP immédiat", ->
      package.loaded["ffi_defs"].libnfq.nfq_get_payload = -> -1
      rc = wq.handle_question nil, nil, 1
      assert.equals 0, rc

    it "MAC source inconnue (mac_raw absent) : la question reste traitée", ->
      decision = { verdict: true, reason: "ok", rule_id: "r_mac" }
      package.loaded["nfq/ethernet"].get_l2 = -> {
        mac_src: "unknown"
        mac_raw: nil
        in_ifindex: 5
        vlan: nil
      }
      rc = invoke ipv4_udp DNS_QUERY
      assert.equals 1, rc
      msg = ipc.decode_msg read_fd pipe_r
      assert.equals ipc.MSG_IPV4, msg.msg_type

    it "sans pipe d'événements, write_event est un no-op", ->
      decision = { verdict: true, reason: "ok", rule_id: "r_noev" }
      wq.run 0, pipe_w, nil, nil, nil
      rc = invoke ipv4_udp DNS_QUERY
      assert.equals 1, rc
      msg = ipc.decode_msg read_fd pipe_r
      assert.equals "r_noev", msg.rule_id
