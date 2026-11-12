-- tests/unit/lib/nfq_rcvbuf_spec.moon
-- Taille du tampon de réception netlink des files NFQUEUE (SO_RCVBUF /
-- SO_RCVBUFFORCE) : valeur demandée (config ou profil RAM faible), valeur
-- obtenue relue par getsockopt, repli quand le noyau borne la valeur ou quand
-- l'appel échoue, et journalisation INFO/WARN.

ffi = require "ffi"

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

-- Types POSIX : ffi_defs est stubbé par tests/helpers/busted_setup.lua.
pcall ->
  ffi.cdef [[
    typedef unsigned int socklen_t;
    int setsockopt(int sockfd, int level, int optname,
                   const void *optval, socklen_t optlen);
    int getsockopt(int sockfd, int level, int optname,
                   void *optval, socklen_t *optlen);
  ]]

errno_box = ffi.new "int[1]", 0

--- Faux libc scripté : mémorise les setsockopt et rend les valeurs
-- successives de getsockopt (la première après SO_RCVBUF, la suivante après
-- SO_RCVBUFFORCE).
-- @tparam table opts { values, rcvbuf_rc, force_ok, errno }
make_libc = (opts = {}) ->
  calls = {}
  state = { get_idx: 0, force_ok: opts.force_ok != false, errno: opts.errno or 9 }
  values = opts.values or { 8388608 }
  libc = {
    __errno_location: -> errno_box
    setsockopt: (fd, level, optname, optval, optlen) ->
      val = ffi.cast "int*", optval
      calls[#calls + 1] = { :fd, :level, :optname, value: val[0] }
      if optname == 8   -- SO_RCVBUF
        errno_box[0] = state.errno
        return opts.rcvbuf_rc or 0
      errno_box[0] = 1   -- EPERM (SO_RCVBUFFORCE sans CAP_NET_ADMIN)
      state.force_ok and 0 or -1
    getsockopt: (fd, level, optname, optval, optlen) ->
      state.get_idx += 1
      idx = math.min state.get_idx, #values
      ffi.cast("int*", optval)[0] = values[idx]
      ffi.cast("socklen_t*", optlen)[0] = 4
      0
  }
  libc, calls

orig_log = package.loaded["log"]
logged = {}
log_stub = {
  log_info: (thunk) -> logged[#logged + 1] = { level: "INFO", fields: thunk! }
  log_warn: (thunk) -> logged[#logged + 1] = { level: "WARN", fields: thunk! }
  log_debug: (->)
}

describe "lib.nfq_rcvbuf", ->
  rcvbuf = nil

  setup ->
    package.loaded["log"] = log_stub
    package.loaded["lib.nfq_rcvbuf"] = nil
    rcvbuf = require "lib.nfq_rcvbuf"

  teardown ->
    package.loaded["log"] = orig_log
    package.loaded["lib.nfq_rcvbuf"] = nil

  before_each ->
    logged = {}
    errno_box[0] = 0

  describe "resolve_requested", ->
    it "défaut 4 Mio sans configuration", ->
      assert.are.equal 4194304, rcvbuf.resolve_requested nil, false

    it "profil RAM faible → 512 Kio", ->
      assert.are.equal 524288, rcvbuf.resolve_requested nil, true

    it "valeur explicite (octets) prioritaire, y compris en RAM faible", ->
      assert.are.equal 1048576, rcvbuf.resolve_requested 1048576, true

    it "valeur nulle, négative ou non numérique → défaut du profil", ->
      assert.are.equal 4194304, rcvbuf.resolve_requested 0, false
      assert.are.equal 4194304, rcvbuf.resolve_requested -1, false
      assert.are.equal 4194304, rcvbuf.resolve_requested "abc", false

  describe "apply_rcvbuf", ->
    it "demande la taille avec SO_RCVBUF et relit la valeur obtenue", ->
      libc, calls = make_libc { values: { 8388608 } }
      res = rcvbuf.apply_rcvbuf libc, 9, 4194304
      assert.are.equal 4194304, res.requested
      assert.are.equal 8388608, res.obtained
      assert.is_false res.forced
      assert.are.equal 1, #calls
      assert.are.equal 9, calls[1].fd
      assert.are.equal 1, calls[1].level   -- SOL_SOCKET
      assert.are.equal 8, calls[1].optname -- SO_RCVBUF
      assert.are.equal 4194304, calls[1].value

    it "valeur bornée par le noyau : repli SO_RCVBUFFORCE (root)", ->
      libc, calls = make_libc { values: { 212992, 8388608 } }
      res = rcvbuf.apply_rcvbuf libc, 9, 4194304
      assert.is_true res.forced
      assert.are.equal 8388608, res.obtained
      assert.are.equal 2, #calls
      assert.are.equal 33, calls[2].optname -- SO_RCVBUFFORCE
      assert.are.equal 4194304, calls[2].value

    it "SO_RCVBUFFORCE refusé (EPERM) : garde la valeur bornée, sans erreur", ->
      libc, calls = make_libc { values: { 212992, 212992 }, force_ok: false }
      res = rcvbuf.apply_rcvbuf libc, 9, 4194304
      assert.is_false res.forced
      assert.are.equal 212992, res.obtained
      assert.is_nil res.error
      assert.are.equal 2, #calls

    it "échec de SO_RCVBUF : obtenue nulle, errno remonté, pas de FORCE", ->
      libc, calls = make_libc { rcvbuf_rc: -1, errno: 22 }
      res = rcvbuf.apply_rcvbuf libc, 9, 4194304
      assert.is_nil res.obtained
      assert.are.equal 22, res.error
      assert.are.equal 1, #calls
      assert.are.equal 8, calls[1].optname

    it "libc sans setsockopt/getsockopt (stub de test) → nil, aucun log", ->
      assert.is_nil rcvbuf.apply_rcvbuf {}, 9, 4194304
      assert.is_nil rcvbuf.configure nil, 9, 0, nil, false
      assert.are.equal 0, #logged

  describe "configure", ->
    it "log INFO de la taille effective (avec forced)", ->
      libc = make_libc { values: { 8388608 } }
      res = rcvbuf.configure libc, 9, 14, nil, false
      assert.are.equal 8388608, res.obtained
      assert.are.equal 1, #logged
      assert.are.equal "INFO", logged[1].level
      assert.are.equal "queue_rcvbuf", logged[1].fields.action
      assert.are.equal 14, logged[1].fields.queue
      assert.are.equal 4194304, logged[1].fields.requested
      assert.are.equal 8388608, logged[1].fields.obtained
      assert.is_false logged[1].fields.forced

    it "WARN si la valeur obtenue reste inférieure à la demande", ->
      libc = make_libc { values: { 212992, 212992 }, force_ok: false }
      rcvbuf.configure libc, 9, 15, 4194304, false
      assert.are.equal 2, #logged
      assert.are.equal "WARN", logged[2].level
      assert.are.equal "queue_rcvbuf_below_requested", logged[2].fields.action
      assert.are.equal 4194304, logged[2].fields.requested
      assert.are.equal 212992, logged[2].fields.obtained

    it "WARN si setsockopt échoue (errno dans le message)", ->
      libc = make_libc { rcvbuf_rc: -1, errno: 22 }
      res = rcvbuf.configure libc, 9, 4, nil, false
      assert.is_nil res.obtained
      assert.are.equal 1, #logged
      assert.are.equal "WARN", logged[1].level
      assert.are.equal "queue_rcvbuf_failed", logged[1].fields.action
      assert.are.equal 22, logged[1].fields.errno

    it "profil RAM faible sans clé explicite → demande 512 Kio", ->
      libc, calls = make_libc { values: { 1048576 } }
      rcvbuf.configure libc, 9, 0, nil, true
      assert.are.equal 524288, calls[1].value
      assert.are.equal 524288, logged[1].fields.requested
