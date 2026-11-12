-- tests/unit/worker_responses_bus_spec.moon
-- Bus de verdicts « second avis » entre workers réponses (multi-worker).
--
-- Avec plusieurs files réponses, la réponse du validateur (B) peut arriver dans
-- un autre processus que la réponse d'origine (A) qu'elle doit débloquer :
-- couples d'adresses différents → files différentes (hachage de flux du noyau).
-- Chaque worker diffuse donc son verdict B sur le pipe dédié des autres
-- (`broadcast_verdict`) et chacun applique ce qu'il reçoit (`drain_verdict_bus`).
-- Ici : pipes réels, `finalize_a` remplacé par un espion (aucun paquet forgé).

ffi = require "ffi"

for decl in *{
  "int  pipe2(int pipefd[2], int flags);"
  "int  close(int fd);"
  "long read(int fd, void *buf, unsigned long count);"
  "long write(int fd, const void *buf, unsigned long count);"
  "int* __errno_location(void);"
  "struct pollfd { int fd; short events; short revents; };"
}
  pcall ffi.cdef, decl

O_NONBLOCK = 2048

make_pipe = ->
  fds = ffi.new "int[2]"
  assert.equals 0, ffi.C.pipe2 fds, O_NONBLOCK
  { fds[0], fds[1] }

close_pipe = (p) ->
  ffi.C.close p[1]
  ffi.C.close p[2]

read_all = (fd) ->
  buf = ffi.new "char[8192]"
  out = ""
  while true
    n = tonumber ffi.C.read fd, buf, 8192
    break if not n or n <= 0
    out ..= ffi.string buf, n
  out

fresh_worker_responses = ->
  package.loaded["worker_responses"] = nil
  dofile "lua/worker_responses.lua"

so_mod = require "second_opinion"

describe "worker_responses bus de verdicts (multi-worker)", ->
  m = nil
  so = nil
  released = nil

  before_each ->
    config = require "config"
    config.runtime = { benchmark: false }
    m = fresh_worker_responses!
    so = so_mod.new resolvers: { "94.130.180.225" }
    m._set_so_state so
    released = {}
    m._set_finalize_impl (ctx, override) -> released[#released + 1] = { :ctx, :override }

  it "broadcast_verdict écrit la même ligne décodable dans tous les pipes", ->
    p1 = make_pipe!
    p2 = make_pipe!
    m._set_so_bus nil, { p1[2], p2[2] }

    m.broadcast_verdict "192.0.2.10", 0x1234, "Example.COM", { kind: "block" }

    for p in *{ p1, p2 }
      line = read_all p[1]
      assert.is_true #line > 0
      rec, err = so_mod.decode_verdict line
      assert.is_nil err
      assert.equals "192.0.2.10", rec.client_ip
      assert.equals 0x1234, rec.txid
      assert.equals "block", rec.override.kind

    close_pipe p1
    close_pipe p2

  it "broadcast_verdict sans bus (1 worker) ne fait rien", ->
    m._set_so_bus nil, nil
    assert.is_nil m.broadcast_verdict "192.0.2.10", 1, "a.test", { kind: "pass" }

  it "drain_verdict_bus libère la réponse A parquée avec le verdict reçu", ->
    p = make_pipe!
    m._set_so_bus p[1], {}
    ctx = { id: "A", defer: true }
    so.park (so.corr_key "192.0.2.10", 0x1234, "example.com"), ctx, 0
    line = so_mod.encode_verdict "192.0.2.10", 0x1234, "example.com", { kind: "block" }
    ffi.C.write p[2], line, #line

    n = m.drain_verdict_bus true
    assert.equals 1, n
    assert.equals 1, #released
    assert.equals ctx, released[1].ctx
    assert.equals "block", released[1].override.kind
    assert.is_true ctx.defer
    assert.is_false so.has_parked!

    close_pipe p

  it "drain_verdict_bus mémorise le verdict si A n'est pas encore parquée", ->
    p = make_pipe!
    m._set_so_bus p[1], {}
    line = so_mod.encode_verdict "192.0.2.10", 0x4321, "b.test", { kind: "pass" }
    ffi.C.write p[2], line, #line

    n = m.drain_verdict_bus false
    assert.equals 0, n
    assert.equals 0, #released
    got = so.take_verdict (so.corr_key "192.0.2.10", 0x4321, "b.test"), os.time!
    assert.equals "pass", got and got.kind

    close_pipe p

  it "drain_verdict_bus gère une ligne coupée en deux écritures", ->
    p = make_pipe!
    m._set_so_bus p[1], {}
    ctx = { id: "A", defer: true }
    so.park (so.corr_key "192.0.2.10", 7, "c.test"), ctx, 0
    line = so_mod.encode_verdict "192.0.2.10", 7, "c.test", { kind: "block" }
    half = math.floor #line / 2
    ffi.C.write p[2], line\sub(1, half), half
    assert.equals 0, m.drain_verdict_bus true   -- ligne incomplète : rien
    rest = #line - half
    ffi.C.write p[2], line\sub(half + 1), rest
    assert.equals 1, m.drain_verdict_bus true   -- ligne complétée : libérée
    assert.equals 1, #released
    close_pipe p

  it "drain_verdict_bus ignore une ligne invalide sans tuer le worker", ->
    p = make_pipe!
    m._set_so_bus p[1], {}
    ffi.C.write p[2], "pas un verdict\n", 15
    assert.equals 0, m.drain_verdict_bus false
    assert.equals 0, #released
    close_pipe p

  it "drain_verdict_bus sans pipe retourne 0", ->
    m._set_so_bus nil, nil
    assert.equals 0, m.drain_verdict_bus false
