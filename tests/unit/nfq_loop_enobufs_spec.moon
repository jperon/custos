-- tests/unit/nfq_loop_enobufs_spec.moon
-- T9 : branches ENOBUFS / EINTR de run_queue (anti-tempête sous charge et
-- interruption par signal). Faux libnfq + libc.read/poll scriptés, restaurés
-- en teardown ; aucun fd ni queue réelle.

ffi = require "ffi"

-- lib.socket déclare struct pollfd, poll, read, __errno_location, ntohl.
pcall require, "lib.socket"

-- Types NFQUEUE normalement fournis par ffi_defs (stubbé dans les tests).
for decl in *{
  "typedef struct nfq_q_handle nfq_q_handle;"
  "typedef struct nfq_handle nfq_handle;"
  "typedef struct nfgenmsg nfgenmsg;"
  "typedef struct nfq_data nfq_data;"
  "typedef int (*nfq_callback)(nfq_q_handle *qh, nfgenmsg *nfmsg, nfq_data *nfad, void *data);"
  "int getpid(void);"
}
  pcall ffi.cdef, decl

orig_defs = package.loaded["ffi_defs"]
orig_nfq  = package.loaded["nfq_loop"]

reads = {}
read_idx = 0
poll_script = {}
poll_idx = 0
errno_box = ffi.new "int[1]"
handled = {}
destroyed = 0
closed = 0
idle_calls = 0

package.loaded["ffi_defs"] = {
  :ffi
  libc: {
    read: (fd, buf, count) ->
      read_idx += 1
      r = reads[read_idx] or { rv: 0 }
      errno_box[0] = r.errno or 0
      ffi.fill buf, r.rv, 0x78 if r.rv and r.rv > 0
      r.rv
    poll: (pfd, nfds, timeout) ->
      poll_idx += 1
      r = poll_script[poll_idx] or { rv: 0 }
      errno_box[0] = r.errno or 0
      r.rv
    __errno_location: -> errno_box
  }
  libnfq: {
    nfq_open: -> ffi.cast "nfq_handle*", 0x1000
    nfq_bind_pf: (h, pf) -> 0
    nfq_create_queue: (h, num, cb, data) -> ffi.cast "nfq_q_handle*", 0x2000
    nfq_set_mode: (qh, mode, range) -> 0
    nfq_fd: (h) -> 99
    nfq_handle_packet: (h, buf, len) ->
      handled[#handled + 1] = tonumber len
      0
    nfq_destroy_queue: (qh) ->
      destroyed += 1
      0
    nfq_close: (h) ->
      closed += 1
      0
  }
}

package.loaded["nfq_loop"] = nil
nfq = require "nfq_loop"

describe "nfq_loop.run_queue ENOBUFS/EINTR", ->
  teardown ->
    package.loaded["ffi_defs"] = orig_defs
    package.loaded["nfq_loop"] = orig_nfq

  before_each ->
    reads = {}
    read_idx = 0
    poll_script = {}
    poll_idx = 0
    handled = {}
    destroyed = 0
    closed = 0
    idle_calls = 0

  it "ENOBUFS ne fait pas sortir la boucle (poursuite jusqu'à EOF)", ->
    reads = {
      { rv: -1, errno: 105 }   -- ENOBUFS
      { rv: 0 }                -- EOF
    }
    nfq.run_queue 0, -> 1
    assert.equals 2, read_idx
    assert.equals 0, #handled
    assert.equals 1, destroyed
    assert.equals 1, closed

  it "après ENOBUFS, traite le paquet suivant puis sort sur EINTR", ->
    reads = {
      { rv: -1, errno: 105 }   -- ENOBUFS
      { rv: 10 }               -- paquet
      { rv: -1, errno: 4 }     -- EINTR → sortie propre
    }
    nfq.run_queue 0, -> 1
    assert.equals 3, read_idx
    assert.same { 10 }, handled
    assert.equals 1, destroyed
    assert.equals 1, closed

  it "supporte une longue série d'ENOBUFS (compteur anti-spam)", ->
    for i = 1, 257
      reads[i] = { rv: -1, errno: 105 }
    reads[258] = { rv: 0 }
    nfq.run_queue 0, -> 1
    assert.equals 258, read_idx
    assert.equals 0, #handled
    assert.equals 1, destroyed

  it "EINTR en lecture → sortie propre de la boucle", ->
    reads = { { rv: -1, errno: 4 } }
    nfq.run_queue 0, -> 1
    assert.equals 1, read_idx
    assert.equals 1, destroyed
    assert.equals 1, closed

  it "poll EINTR → continue, puis lecture interrompue → sortie", ->
    poll_script = {
      { rv: -1, errno: 4 }   -- EINTR sur poll
      { rv: 1 }              -- prêt à lire
    }
    reads = { { rv: -1, errno: 4 } }
    nfq.run_queue 0, (-> 1), {
      idle_ms: 10
      on_idle: -> idle_calls += 1
    }
    assert.equals 2, poll_idx
    assert.equals 2, idle_calls
    assert.equals 1, read_idx
    assert.equals 1, destroyed

  it "erreur de poll autre que EINTR → sortie avec libération", ->
    poll_script = { { rv: -1, errno: 5 } }   -- EIO
    nfq.run_queue 0, (-> 1), { idle_ms: 10, on_idle: -> nil }
    assert.equals 1, poll_idx
    assert.equals 0, read_idx
    assert.equals 1, destroyed
    assert.equals 1, closed

describe "nfq_loop.run_queue on_batch_end (verdicts différés)", ->
  teardown ->
    package.loaded["ffi_defs"] = orig_defs
    package.loaded["nfq_loop"] = orig_nfq

  before_each ->
    reads = {}
    read_idx = 0
    poll_script = {}
    poll_idx = 0
    handled = {}
    destroyed = 0
    closed = 0
    idle_calls = 0

  it "regroupe en un seul lot les paquets déjà présents dans le socket (drain)", ->
    batch = {}
    reads = {
      { rv: 10 }                -- lecture bloquante : paquet 1
      { rv: 20 }                -- drain : paquet 2
      { rv: 30 }                -- drain : paquet 3
      { rv: -1, errno: 11 }     -- drain : EAGAIN (socket vidé) → fin du lot
      { rv: 0 }                 -- lecture suivante : EOF
    }
    poll_script = { { rv: 1 }, { rv: 1 }, { rv: 1 } }
    nfq.run_queue 0, (-> 1), { on_batch_end: -> batch[#batch + 1] = #handled }
    -- Lot de 3 paquets (un seul on_batch_end), puis flush de sortie sur EOF.
    assert.same { 3, 3 }, batch
    assert.same { 10, 20, 30 }, handled
    assert.equals 3, poll_idx
    assert.equals 1, destroyed

  it "un seul paquet par lot quand le socket n'a rien de plus", ->
    batch = {}
    reads = { { rv: 10 }, { rv: 0 } }
    poll_script = { { rv: 0 } }   -- rien à drainer
    nfq.run_queue 0, (-> 1), { on_batch_end: -> batch[#batch + 1] = #handled }
    assert.same { 1, 1 }, batch
    assert.same { 10 }, handled
    assert.equals 1, poll_idx

  it "borne un lot à MAX_BATCH_PKTS (64) paquets", ->
    batch = {}
    for i = 1, 100
      reads[i] = { rv: 1 }
    reads[101] = { rv: 0 }
    for i = 1, 99
      poll_script[i] = { rv: 1 }
    poll_script[100] = { rv: 0 }   -- le socket est vide après le drain du 2e lot
    nfq.run_queue 0, (-> 1), { on_batch_end: -> batch[#batch + 1] = #handled }
    assert.equals 64, batch[1]
    assert.equals 100, #handled
    assert.equals 100, batch[#batch]

  it "sans on_batch_end, aucun drain ni appel de hook", ->
    reads = { { rv: 10 }, { rv: 20 }, { rv: 0 } }
    nfq.run_queue 0, (-> 1)
    assert.same { 10, 20 }, handled
    assert.equals 0, poll_idx
    assert.equals 1, closed
