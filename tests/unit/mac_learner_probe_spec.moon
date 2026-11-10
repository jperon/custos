-- tests/unit/mac_learner_probe_spec.moon
-- Décision d'envoi de probe ARP/NS pour une IP inconnue (probe_request),
-- extraite de start_query pour être testable sans boucle poll.
-- Régression : un échec de send_probe doit répondre "unknown", fermer le fd
-- et poser le cache négatif (avant : fd fuit, client bloqué).

{ :ffi, :libc } = require "ffi_defs"
ml = require "mac_learner"

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
    pending, negative = {}, {}
    client_fd, peer = mk_pair!
    out = ml.probe_request pending, negative, {}, client_fd, "10.0.0.1",
      1000, (-> 0), (-> false)
    assert.equals "failed", out
    assert.equals "unknown\n", read_all peer, 8
    assert.equals 1030, negative["10.0.0.1"]
    assert.is_nil next pending
    assert.equals -1, libc.close client_fd   -- déjà fermé par probe_request
    libc.close peer

  it "send_probe lève une erreur → même comportement", ->
    pending, negative = {}, {}
    client_fd, peer = mk_pair!
    out = ml.probe_request pending, negative, {}, client_fd, "10.0.0.2",
      2000, (-> 0), (-> error "boom")
    assert.equals "failed", out
    assert.equals "unknown\n", read_all peer, 8
    assert.equals 2030, negative["10.0.0.2"]
    assert.is_nil next pending
    assert.equals -1, libc.close client_fd
    libc.close peer

  it "send_probe ok → fd gardé ouvert et présent dans pending_queries", ->
    pending, negative = {}, {}
    client_fd, peer = mk_pair!
    out = ml.probe_request pending, negative, {}, client_fd, "10.0.0.3",
      3000, (-> 0), (-> true)
    assert.equals "pending", out
    assert.is_nil negative["10.0.0.3"]
    assert.equals client_fd, pending["10.0.0.3"][1][1]
    assert.equals 200, pending["10.0.0.3"][1][2]
    assert.equals 0, libc.close client_fd   -- toujours ouvert : fermeture réussit
    libc.close peer

  it "probe déjà en vol → client ajouté sans nouvelle sonde", ->
    pending = {}
    pending["10.0.0.4"] = { { 42, 0 } }
    negative = {}
    client_fd, peer = mk_pair!
    calls = 0
    send = ->
      calls += 1
      true
    out = ml.probe_request pending, negative, {}, client_fd, "10.0.0.4",
      4000, (-> 0), send
    assert.equals "joined", out
    assert.equals 0, calls
    assert.equals 2, #pending["10.0.0.4"]
    assert.equals client_fd, pending["10.0.0.4"][2][1]
    assert.equals 0, libc.close client_fd
    libc.close peer
