-- tests/unit/mac_learner_probe_spec.moon
-- Décision d'envoi de probe ARP/NS pour une IP inconnue (probe_request),
-- extraite de start_query pour être testable sans boucle poll.
-- Régression : un échec de send_probe doit répondre "unknown", fermer le fd
-- et poser le cache négatif (avant : fd fuit, client bloqué).

{ :ffi, :libc } = require "ffi_defs"
ml = require "mac_learner"
ttl_set = require "lib.ttl_set"

-- Cache négatif contrôlable : ttl_set avec horloge injectée (TTL 30 s).
make_negative = (t) -> ttl_set.new 100, 30, -> t.v

pcall -> ffi.cdef "int socketpair(int domain, int type, int protocol, int sv[2]);"

AF_UNIX = 1
SOCK_STREAM = 1

mk_pair = ->
  sv = ffi.new "int[2]"
  ret = libc.socketpair AF_UNIX, SOCK_STREAM, 0, sv
  assert.equals 0, ret
  sv[0], sv[1]

read_all = (fd, n) ->
  buf = ffi.new "char[?]", n
  got = libc.recv fd, buf, n, 0
  return nil if got < 0
  ffi.string buf, got

describe "mac_learner probe_request", ->
  it "send_probe renvoie false → unknown envoyé, fd fermé, cache négatif", ->
    pending = {}
    t = { v: 1000 }
    negative = make_negative t
    client_fd, peer = mk_pair!
    out = ml.probe_request pending, negative, {}, client_fd, "10.0.0.1",
      (-> 0), (-> false)
    assert.equals "failed", out
    assert.equals "unknown\n", read_all peer, 8
    assert.is_true negative.has "10.0.0.1"
    t.v = 1030
    assert.is_false negative.has "10.0.0.1"   -- TTL 30 s écoulé
    assert.is_nil next pending
    assert.equals -1, libc.close client_fd   -- déjà fermé par probe_request
    libc.close peer

  it "send_probe lève une erreur → même comportement", ->
    pending = {}
    t = { v: 2000 }
    negative = make_negative t
    client_fd, peer = mk_pair!
    out = ml.probe_request pending, negative, {}, client_fd, "10.0.0.2",
      (-> 0), (-> error "boom")
    assert.equals "failed", out
    assert.equals "unknown\n", read_all peer, 8
    assert.is_true negative.has "10.0.0.2"
    assert.is_nil next pending
    assert.equals -1, libc.close client_fd
    libc.close peer

  it "send_probe ok → fd gardé ouvert et présent dans pending_queries", ->
    pending = {}
    t = { v: 3000 }
    negative = make_negative t
    client_fd, peer = mk_pair!
    out = ml.probe_request pending, negative, {}, client_fd, "10.0.0.3",
      (-> 0), (-> true)
    assert.equals "pending", out
    assert.is_false negative.has "10.0.0.3"
    assert.equals client_fd, pending["10.0.0.3"][1][1]
    assert.equals 200, pending["10.0.0.3"][1][2]
    assert.equals 0, libc.close client_fd   -- toujours ouvert : fermeture réussit
    libc.close peer

  it "probe déjà en vol → client ajouté sans nouvelle sonde", ->
    pending = {}
    pending["10.0.0.4"] = { { 42, 0 } }
    negative = make_negative { v: 4000 }
    client_fd, peer = mk_pair!
    calls = 0
    send = ->
      calls += 1
      true
    out = ml.probe_request pending, negative, {}, client_fd, "10.0.0.4",
      (-> 0), send
    assert.equals "joined", out
    assert.equals 0, calls
    assert.equals 2, #pending["10.0.0.4"]
    assert.equals client_fd, pending["10.0.0.4"][2][1]
    assert.equals 0, libc.close client_fd
    libc.close peer

-- ── Bornage temporel des recv (learner figé / client muet) ────────────────
-- Sans SO_RCVTIMEO, un pair muet bloque l'unique boucle poll du learner
-- (côté serveur) ou le plan de données appelant (côté client).

pcall -> ffi.cdef "int clock_gettime(int clk_id, timespec_t *tp);"
CLOCK_MONOTONIC = 1
now_ms = ->
  ts = ffi.new "timespec_t"
  ffi.C.clock_gettime CLOCK_MONOTONIC, ts
  tonumber(ts.tv_sec) * 1000 + math.floor(tonumber(ts.tv_nsec) / 1000000)

describe "mac_learner start_query borné", ->
  it "client muet (n'écrit jamais) → recv abandonné, fd fermé, retour rapide", ->
    client_fd, peer = mk_pair!
    t0 = now_ms!
    ml.start_query client_fd
    elapsed = now_ms! - t0
    assert.is_true elapsed < 1000, "start_query a bloqué #{elapsed} ms"
    assert.equals -1, libc.close client_fd   -- déjà fermé
    libc.close peer

describe "mac_learner_ipc query borné", ->
  orig_defs = nil
  old_cfg = nil
  before_each ->
    orig_defs = package.loaded["ffi_defs"]
    old_cfg = package.loaded["config"]
    package.loaded["mac_learner_ipc"] = nil
  after_each ->
    package.loaded["ffi_defs"] = orig_defs
    package.loaded["config"] = old_cfg
    package.loaded["mac_learner_ipc"] = nil

  it "serveur muet → client rend la main en < 1 s avec « unknown »", ->
    client_fd, peer = mk_pair!
    mock = {
      socket: -> client_fd
      connect: -> 0
      send: (s, b, n, f) -> ffi.C.send s, b, n, f
      recv: (s, b, n, f) -> ffi.C.recv s, b, n, f
      close: (fd) -> ffi.C.close fd
      setsockopt: (s, lvl, opt, val, len) -> ffi.C.setsockopt s, lvl, opt, val, len
      __errno_location: -> ffi.C.__errno_location!
    }
    package.loaded["ffi_defs"] = { ffi: ffi, libc: mock, libnfq: {}, libnft: {} }
    ipc = require "mac_learner_ipc"
    t0 = now_ms!
    result = ipc.get_mac "10.0.0.1"
    elapsed = now_ms! - t0
    assert.equals "unknown", result
    assert.is_true elapsed < 1000, "get_mac a bloqué #{elapsed} ms"
    libc.close peer

describe "mac_learner.ip16_to_str heuristique de famille", ->
  it "IPv4 10.0.0.5 encodée sur 16 octets (octets 5-16 nuls) → forme IPv4", ->
    ip16 = string.char(10, 0, 0, 5) .. string.rep("\0", 12)
    assert.equals "10.0.0.5", ml.ip16_to_str ip16

  it "IPv6 2001:db8::1 → forme IPv6", ->
    ip16 = string.char(0x20, 0x01, 0x0d, 0xb8) .. string.rep("\0", 11) .. string.char(1)
    assert.equals "2001:db8::1", ml.ip16_to_str ip16
