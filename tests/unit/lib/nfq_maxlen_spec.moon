-- tests/unit/lib/nfq_maxlen_spec.moon
-- Longueur de la file noyau des files NFQUEUE (nfq_set_queue_maxlen) :
-- valeur demandée (config ou profil RAM faible), appel FFI, et journalisation
-- INFO/WARN. Le noyau jette les paquets quand cette file est pleine
-- (`queue_dropped`, colonne 6 de /proc/net/netfilter/nfnetlink_queue) avant
-- même qu'ils atteignent le socket userspace.

ffi = require "ffi"

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

errno_box = ffi.new "int[1]", 0

--- Faux libnfq scripté : mémorise les appels à nfq_set_queue_maxlen et rend
-- le code de retour demandé.
-- @tparam table opts { rc }
make_libnfq = (opts = {}) ->
  calls = {}
  libnfq = {
    nfq_set_queue_maxlen: (qh, maxlen) ->
      calls[#calls + 1] = { :qh, :maxlen }
      opts.rc or 0
  }
  libnfq, calls

stub_libc = { __errno_location: -> errno_box }

orig_log = package.loaded["log"]
logged = {}
log_stub = {
  log_info: (thunk) -> logged[#logged + 1] = { level: "INFO", fields: thunk! }
  log_warn: (thunk) -> logged[#logged + 1] = { level: "WARN", fields: thunk! }
  log_debug: (->)
}

describe "lib.nfq_maxlen", ->
  maxlen = nil

  setup ->
    package.loaded["log"] = log_stub
    package.loaded["lib.nfq_maxlen"] = nil
    maxlen = require "lib.nfq_maxlen"

  teardown ->
    package.loaded["log"] = orig_log
    package.loaded["lib.nfq_maxlen"] = nil

  before_each ->
    logged = {}
    errno_box[0] = 0

  describe "resolve_maxlen", ->
    it "défaut 4096 sans configuration", ->
      assert.are.equal 4096, maxlen.resolve_maxlen nil, false

    it "profil RAM faible → 1024", ->
      assert.are.equal 1024, maxlen.resolve_maxlen nil, true

    it "valeur explicite prioritaire, y compris en RAM faible", ->
      assert.are.equal 2048, maxlen.resolve_maxlen 2048, true

    it "valeur textuelle acceptée", ->
      assert.are.equal 8192, maxlen.resolve_maxlen "8192", false

    it "valeur nulle, négative, non numérique ou non entière → défaut du profil", ->
      assert.are.equal 4096, maxlen.resolve_maxlen 0, false
      assert.are.equal 4096, maxlen.resolve_maxlen -1, false
      assert.are.equal 4096, maxlen.resolve_maxlen "abc", false
      assert.are.equal 4096, maxlen.resolve_maxlen 12.5, false
      assert.are.equal 1024, maxlen.resolve_maxlen nil, true

  describe "apply_maxlen", ->
    it "appelle nfq_set_queue_maxlen avec la valeur demandée", ->
      libnfq, calls = make_libnfq!
      res = maxlen.apply_maxlen libnfq, "qh", 4096
      assert.is_true res.ok
      assert.are.equal 0, res.rc
      assert.are.equal 1, #calls
      assert.are.equal "qh", calls[1].qh
      assert.are.equal 4096, calls[1].maxlen

    it "retour négatif : ok=false, rc conservé", ->
      libnfq, calls = make_libnfq { rc: -1 }
      res = maxlen.apply_maxlen libnfq, "qh", 4096
      assert.is_false res.ok
      assert.are.equal -1, res.rc
      assert.are.equal 1, #calls

    it "libnfq sans nfq_set_queue_maxlen (stub de test) → nil", ->
      assert.is_nil maxlen.apply_maxlen {}, "qh", 4096
      assert.is_nil maxlen.configure nil, stub_libc, "qh", 0, nil, false
      assert.are.equal 0, #logged

  describe "configure", ->
    it "log INFO queue_maxlen (queue, maxlen) au succès", ->
      libnfq, calls = make_libnfq!
      res = maxlen.configure libnfq, stub_libc, "qh", 14, nil, false
      assert.is_true res.ok
      assert.are.equal 4096, calls[1].maxlen
      assert.are.equal 1, #logged
      assert.are.equal "INFO", logged[1].level
      assert.are.equal "queue_maxlen", logged[1].fields.action
      assert.are.equal 14, logged[1].fields.queue
      assert.are.equal 4096, logged[1].fields.maxlen
      assert.is_nil logged[1].fields.errno

    it "valeur explicite journalisée telle quelle (config)", ->
      libnfq, calls = make_libnfq!
      maxlen.configure libnfq, stub_libc, "qh", 4, 16384, true
      assert.are.equal 16384, calls[1].maxlen
      assert.are.equal 16384, logged[1].fields.maxlen

    it "profil RAM faible sans clé explicite → 1024", ->
      libnfq, calls = make_libnfq!
      maxlen.configure libnfq, stub_libc, "qh", 0, nil, true
      assert.are.equal 1024, calls[1].maxlen
      assert.are.equal 1024, logged[1].fields.maxlen

    it "WARN queue_maxlen_failed si le retour est négatif (errno joint)", ->
      libnfq, calls = make_libnfq { rc: -1 }
      errno_box[0] = 22
      res = maxlen.configure libnfq, stub_libc, "qh", 15, nil, true
      assert.is_false res.ok
      assert.are.equal 1, #logged
      assert.are.equal "WARN", logged[1].level
      assert.are.equal "queue_maxlen_failed", logged[1].fields.action
      assert.are.equal 15, logged[1].fields.queue
      assert.are.equal 1024, logged[1].fields.maxlen
      assert.are.equal 22, logged[1].fields.errno
