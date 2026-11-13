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
pcall ffi.cdef, [[
  struct pollfd { int fd; short events; short revents; };
  int poll(struct pollfd *fds, unsigned long nfds, int timeout);
]]

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
  "log", "lib.netstamp", "lib.pipe_batch"
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

-- Lecture non bloquante : "" si rien n'est disponible (assertion « aucun
-- message IPC/événement » sans bloquer sur un tube vide).
read_available = (fd) ->
  pfd = ffi.new "struct pollfd[1]"
  pfd[0].fd = fd
  pfd[0].events = 1
  n = tonumber ffi.C.poll pfd, 1, 0
  if n and n > 0 then read_fd fd else ""

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
  learn_r = nil
  learn_w = nil
  pipe_r = nil
  pipe_w = nil
  -- Journal des write() effectués via le faux libc (fd + nombre d'octets) :
  -- permet d'affirmer qu'un lot de messages ne coûte qu'UNE écriture.
  write_calls = {}
  -- Captures du câblage run_queue → metrics (P2.3) : les options passées à
  -- run_queue et l'ordre des appels au module metrics.
  captured_opts = nil
  metrics_calls = {}
  -- Âge renvoyé par le stub nfq_loop.packet_age_ms ; nil = horodatage absent.
  stub_age = nil
  -- Captures de l'activation de l'horodatage noyau : le vrai module
  -- lib.netstamp est utilisé, avec un faux libc (socket/setsockopt/close).
  socket_calls = {}
  setsockopt_calls = {}
  closed_fds = {}
  fail_socket = false
  fail_setsockopt = false
  setsockopt_ok = nil
  fake_errno = nil
  -- Captures des logs INFO/WARN émis par worker_questions et lib.netstamp.
  log_infos = {}
  log_warns = {}
  cfg = require "config"

  before_each ->
    save_all!
    decision = nil
    payload  = ""
    captured_opts = nil
    metrics_calls = {}
    stub_age = nil
    socket_calls = {}
    setsockopt_calls = {}
    closed_fds = {}
    fail_socket = false
    fail_setsockopt = false
    setsockopt_ok = nil
    log_infos = {}
    log_warns = {}
    write_calls = {}
    fake_errno = ffi.new "int[1]", 0
    cfg.nfqueue = cfg.nfqueue or {}
    cfg.nfqueue.max_age_ms = 1500

    ev_r, ev_w     = make_pipe!
    learn_r, learn_w = make_pipe!
    pipe_r, pipe_w = make_pipe!

    -- Stub de log : capture INFO/WARN (dont question_shed_timestamp et
    -- netstamp_enable_failed) tout en conservant les autres fonctions.
    base_log = saved["log"] or {}
    log_stub = {}
    for k, v in pairs base_log
      log_stub[k] = v
    log_stub.log_info = (thunk) -> log_infos[#log_infos + 1] = thunk!
    log_stub.log_warn = (thunk) -> log_warns[#log_warns + 1] = thunk!
    package.loaded["log"] = log_stub

    -- Faux libc : les appels sans rapport (write, clock_gettime, …) retombent
    -- sur ffi.C ; socket/setsockopt/close sont scriptés pour vérifier
    -- l'activation de SO_TIMESTAMP sans ouvrir de vrai fd.
    fake_libc = setmetatable {
      __errno_location: -> fake_errno
      write: (fd, buf, n) ->
        write_calls[#write_calls + 1] = { fd: fd, n: tonumber(n) }
        ffi.C.write fd, buf, n
      socket: (domain, type, protocol) ->
        socket_calls[#socket_calls + 1] = { :domain, :type, :protocol }
        if fail_socket
          fake_errno[0] = 97   -- EAFNOSUPPORT
          return -1
        77
      setsockopt: (fd, level, optname, optval, optlen) ->
        val = ffi.cast "int*", optval
        setsockopt_calls[#setsockopt_calls + 1] = {
          :fd, :level, :optname, optlen: optlen, value: val[0]
        }
        ok = false
        if setsockopt_ok
          ok = setsockopt_ok level, optname
        elseif not fail_setsockopt
          ok = true
        if ok
          return 0
        fake_errno[0] = 92   -- ENOPROTOOPT
        -1
      close: (fd) ->
        closed_fds[#closed_fds + 1] = fd
        0
    }, { __index: ffi.C }

    -- Stubs locaux : restaurés en after_each (cf. save_all/restore_all).
    package.loaded["ffi_defs"] = {
      :ffi
      libc: fake_libc
      SO_TIMESTAMP: 29
      SO_TIMESTAMP_NEW: 63
      SOL_SOCKET: 1
      SOL_SOCKET_MIPS: 0xffff
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
      packet_age_ms: (nfad) -> stub_age
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
    package.loaded["dup_query"] = { pick_resolver: -> nil, get_picker: -> -> nil }
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
    package.loaded["lib.netstamp"] = nil
    wq = require "worker_questions"
    wq.run 0, pipe_w, learn_w, ev_w, nil

  after_each ->
    for fd in *{ ev_r, ev_w, learn_r, learn_w, pipe_r, pipe_w }
      ffi.C.close fd if fd
    restore_all!

  -- Un paquet puis vidage des tampons : les assertions de décision ne portent
  -- que sur le contenu, la coalescence des écritures a ses propres tests.
  invoke = (raw) ->
    payload = raw
    rc = wq.handle_question nil, nil, 1
    wq.flush_pipes!
    rc

  find_log = (entries, action) ->
    for entry in *entries
      return entry if entry and entry.action == action
    nil

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
      wq.flush_pipes!
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
      wq.flush_pipes!
      fields = split_tabs read_fd ev_r
      assert.equals "block", fields[2]
      assert.equals "malware.example", fields[3]

  -- ── Écritures groupées vers events et mac_learner ─────────────────────────
  -- Chaque question écrivait une ligne TSV (events) et un message de 22 octets
  -- (learn) : deux write() par paquet. Les messages sont désormais tamponnés et
  -- vidés en fin de lot NFQUEUE (on_batch_end), une écriture par tranche
  -- ≤ PIPE_BUF (cf. docs/agents/perf.md §20).
  describe "écritures groupées (events + learn)", ->
    event_fields = ->
      {
        qname: "example.com", mac_src: "aa:bb:cc:dd:ee:ff"
        src_ip: "192.0.2.10", dst_ip: "1.1.1.1", vlan: 8
        user: nil, af: "ipv4", reason: "ok", rule: "r1"
      }

    writes_on = (fd) ->
      n = 0
      n += 1 for c in *write_calls when c.fd == fd
      n

    it "write_event n'écrit rien avant le vidage, puis une seule écriture", ->
      wq.write_event event_fields!, true
      wq.write_event { qname: "second.example", af: "ipv4" }, false
      assert.equals "", read_available ev_r
      assert.equals 0, writes_on ev_w
      wq.flush_pipes!
      assert.equals 1, writes_on ev_w
      data = read_fd ev_r
      lines = [l for l in data\gmatch "[^\n]+"]
      assert.equals 2, #lines
      assert.equals "allow", split_tabs(lines[1])[2]
      assert.equals "example.com", split_tabs(lines[1])[3]
      assert.equals "block", split_tabs(lines[2])[2]
      assert.equals "second.example", split_tabs(lines[2])[3]

    it "write_learn_msg accumule des messages de 22 octets en une écriture", ->
      assert.is_true wq.write_learn_msg "\192\168\000\010", "\170\187\204\221\238\255"
      assert.is_true wq.write_learn_msg "\192\168\000\011", "\170\187\204\221\238\255"
      assert.equals "", read_available learn_r
      assert.equals 0, writes_on learn_w
      wq.flush_pipes!
      assert.equals 1, writes_on learn_w
      data = read_fd learn_r
      assert.equals 44, #data
      -- ip16 (IPv4 : 4 octets + 12 zéros) puis mac6.
      assert.equals "\192\168\000\010" .. string.rep("\0", 12) .. "\170\187\204\221\238\255",
        data\sub 1, 22
      assert.equals "\192\168\000\011" .. string.rep("\0", 12) .. "\170\187\204\221\238\255",
        data\sub 23, 44

    it "flush_pipes est idempotent et sans effet sur tampon vide", ->
      wq.flush_pipes!
      wq.flush_pipes!
      assert.equals 0, writes_on ev_w
      assert.equals 0, writes_on learn_w

    it "handle_question tamponne événement et apprentissage jusqu'au on_batch_end", ->
      decision = { verdict: true, reason: "ok", rule_id: "r_batch" }
      invoke_without_flush = (raw) ->
        payload = raw
        wq.handle_question nil, nil, 1
      assert.equals 1, invoke_without_flush ipv4_udp DNS_QUERY
      assert.equals "", read_available ev_r
      assert.equals "", read_available learn_r
      assert.is_function captured_opts.on_batch_end
      captured_opts.on_batch_end nil
      ev = read_fd ev_r
      assert.equals "allow", split_tabs(ev)[2]
      learn = read_fd learn_r
      assert.equals 22, #learn

    it "run_queue reçoit on_batch_end même quand les métriques sont coupées", ->
      cfg.metrics = cfg.metrics or {}
      cfg.metrics.enabled = false
      wq.run 0, pipe_w, learn_w, ev_w, nil
      assert.is_function captured_opts.on_batch_end
      assert.is_nil captured_opts.on_idle
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      payload = ipv4_udp DNS_QUERY
      wq.handle_question nil, nil, 1
      assert.equals "", read_available ev_r
      captured_opts.on_batch_end nil
      assert.equals "allow", split_tabs(read_fd ev_r)[2]
      cfg.metrics.enabled = true

  -- ── Délestage précoce des questions périmées (nfqueue.max_age_ms) ─────────
  describe "délestage précoce (question_shed)", ->
    it "jette (NF_DROP) une question plus vieille que le seuil, sans aucun IPC", ->
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      stub_age = 2000
      rc = invoke ipv4_udp DNS_QUERY
      assert.equals 0, rc
      -- Aucune analyse : pas de message IPC, pas d'événement allow/block.
      assert.equals "", read_available pipe_r
      assert.equals "", read_available ev_r
      assert.equals 1, wq.get_shed_total!

    it "ne jette pas à l'âge exact du seuil (comparaison stricte)", ->
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      stub_age = 1500
      rc = invoke ipv4_udp DNS_QUERY
      assert.equals 1, rc
      assert.is_not_nil ipc.decode_msg read_fd pipe_r
      assert.equals 0, wq.get_shed_total!

    it "max_age_ms = 0 désactive le délestage", ->
      cfg.nfqueue.max_age_ms = 0
      wq.run 0, pipe_w, learn_w, ev_w, nil
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      stub_age = 999999
      rc = invoke ipv4_udp DNS_QUERY
      assert.equals 1, rc
      assert.is_not_nil ipc.decode_msg read_fd pipe_r
      assert.equals 0, wq.get_shed_total!

    it "horodatage noyau absent (packet_age_ms nil) : pas de délestage", ->
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      stub_age = nil
      rc = invoke ipv4_udp DNS_QUERY
      assert.equals 1, rc
      assert.is_not_nil ipc.decode_msg read_fd pipe_r
      assert.equals 0, wq.get_shed_total!

    it "compte chaque question jetée, sans compter les servies", ->
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      stub_age = 5000
      assert.equals 0, invoke ipv4_udp DNS_QUERY
      assert.equals 0, invoke ipv4_udp DNS_QUERY
      assert.equals 2, wq.get_shed_total!
      stub_age = 100
      assert.equals 1, invoke ipv4_udp DNS_QUERY
      assert.equals 2, wq.get_shed_total!

  -- ── Activation de l'horodatage noyau (netstamp) ───────────────────────────
  -- Sans socket SO_TIMESTAMP ouvert, `netstamp_needed_key` reste inactive et
  -- NFQA_TIMESTAMP n'est jamais joint : le délestage serait silencieusement
  -- inerte. Ces tests utilisent le vrai lib.netstamp avec un faux libc.
  describe "horodatage noyau (netstamp)", ->
    it "ouvre un socket UDP SO_TIMESTAMP au démarrage quand max_age_ms > 0", ->
      assert.equals 1, #socket_calls
      assert.equals 2, socket_calls[1].domain    -- AF_INET
      assert.equals 2, socket_calls[1].type      -- SOCK_DGRAM
      assert.equals 0, socket_calls[1].protocol
      assert.equals 1, #setsockopt_calls
      assert.equals 77, setsockopt_calls[1].fd
      assert.equals 1, setsockopt_calls[1].level        -- SOL_SOCKET générique
      assert.equals 29, setsockopt_calls[1].optname      -- SO_TIMESTAMP
      assert.equals 1, setsockopt_calls[1].value
      assert.equals 4, setsockopt_calls[1].optlen
      assert.equals 0, #closed_fds
      assert.equals 77, package.loaded["lib.netstamp"].get_fd!

    it "n'ouvre aucun socket quand max_age_ms = 0", ->
      socket_calls = {}
      setsockopt_calls = {}
      cfg.nfqueue.max_age_ms = 0
      wq.run 0, pipe_w, learn_w, ev_w, nil
      assert.equals 0, #socket_calls
      assert.equals 0, #setsockopt_calls

    it "essaie SOL_SOCKET 0xffff après échec du niveau générique (MIPS)", ->
      socket_calls = {}
      setsockopt_calls = {}
      closed_fds = {}
      setsockopt_ok = (level) -> level == 0xffff
      wq.run 0, pipe_w, learn_w, ev_w, nil
      assert.equals 1, #socket_calls
      last = setsockopt_calls[#setsockopt_calls]
      assert.equals 0xffff, last.level
      assert.equals 29, last.optname
      assert.equals 0, #closed_fds

    it "échec de socket : WARN netstamp_enable_failed (stage socket), non fatal", ->
      socket_calls = {}
      setsockopt_calls = {}
      fail_socket = true
      wq.run 0, pipe_w, learn_w, ev_w, nil
      assert.equals 1, #socket_calls
      assert.equals 0, #setsockopt_calls
      warn = find_log log_warns, "netstamp_enable_failed"
      assert.is_not_nil warn
      assert.equals "socket", warn.stage
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      assert.equals 1, invoke ipv4_udp DNS_QUERY

    it "échec de setsockopt : WARN, fd fermé, worker non fatal", ->
      socket_calls = {}
      setsockopt_calls = {}
      closed_fds = {}
      fail_setsockopt = true
      wq.run 0, pipe_w, learn_w, ev_w, nil
      assert.equals 1, #socket_calls
      assert.equals 4, #setsockopt_calls   -- 2 niveaux × 2 variantes
      assert.same { 77 }, closed_fds
      warn = find_log log_warns, "netstamp_enable_failed"
      assert.is_not_nil warn
      assert.equals "setsockopt", warn.stage
      assert.equals 92, warn.errno
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      assert.equals 1, invoke ipv4_udp DNS_QUERY

    it "log INFO unique question_shed_timestamp available=true au premier paquet", ->
      stub_age = 100
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      assert.equals 1, invoke ipv4_udp DNS_QUERY
      assert.equals 1, invoke ipv4_udp DNS_QUERY
      entries = {}
      for entry in *log_infos
        entries[#entries + 1] = entry if entry and entry.action == "question_shed_timestamp"
      assert.equals 1, #entries
      assert.is_true entries[1].available

    it "log INFO unique question_shed_timestamp available=false sans horodatage", ->
      stub_age = nil
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      invoke ipv4_udp DNS_QUERY
      invoke ipv4_udp DNS_QUERY
      entries = {}
      for entry in *log_infos
        entries[#entries + 1] = entry if entry and entry.action == "question_shed_timestamp"
      assert.equals 1, #entries
      assert.is_false entries[1].available

    it "aucun log question_shed_timestamp quand le délestage est désactivé", ->
      cfg.nfqueue.max_age_ms = 0
      wq.run 0, pipe_w, learn_w, ev_w, nil
      decision = { verdict: true, reason: "ok", rule_id: "r1" }
      invoke ipv4_udp DNS_QUERY
      assert.is_nil find_log log_infos, "question_shed_timestamp"

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

    -- Multi-worker réponses : la question est écrite dans le tube de CHAQUE
    -- worker. Un destinataire en échec permanent (worker arrêté, tube plein)
    -- ne doit plus jeter la question (NF_DROP) : sans ce correctif, une file
    -- NFQUEUE inactive menait au blocage définitif (docs/agents/perf.md §12).
    it "un seul destinataire en échec permanent ne jette pas la question", ->
      decision = { verdict: true, reason: "ok", rule_id: "r_fanout" }
      wq.run 0, { -1, pipe_w }, nil, ev_w, nil
      rc = invoke ipv4_udp DNS_QUERY
      assert.equals 1, rc, "question acceptée : le tube sain a reçu la transaction"

      msg = ipc.decode_msg read_fd pipe_r
      assert.equals 0xabcd, msg.txid
      assert.equals "r_fanout", msg.rule_id

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
