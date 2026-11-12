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
poll_fds = {}
errno_box = ffi.new "int[1]"
handled = {}
destroyed = 0
closed = 0
idle_calls = 0
-- Callback C : nfq_create_queue en conserve une référence, nfq_handle_packet
-- l'invoque quand invoke_cb est vrai (sinon le wrapper C n'est jamais exercé).
captured_cb = nil
invoke_cb = false
open_fails = false
create_queue_fails = false
verdict_calls = {}
pcall ffi.cdef, "typedef struct { uint32_t packet_id; } nfqnl_msg_packet_hdr;"
fake_hdr = ffi.new "nfqnl_msg_packet_hdr"

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
      -- revents scriptés (sinon inchangé : les autres specs n'y touchent pas).
      if r.revents
        fds = {}
        for i = 0, nfds - 1
          pfd[i].revents = r.revents[i + 1] or 0
          fds[#fds + 1] = pfd[i].fd
        poll_fds[poll_idx] = fds
      r.rv
    ntohl: (x) -> tonumber x
    __errno_location: -> errno_box
  }
  libnfq: {
    nfq_open: ->
      return nil if open_fails
      ffi.cast "nfq_handle*", 0x1000
    nfq_bind_pf: (h, pf) -> 0
    nfq_get_msg_packet_hdr: (nfad) -> fake_hdr
    nfq_set_verdict: (qh, id, verdict, datalen, buf) ->
      verdict_calls[#verdict_calls + 1] = { :id, :verdict, :datalen, buf_is_nil: buf == nil }
      0
    nfq_create_queue: (h, num, cb, data) ->
      return nil if create_queue_fails
      captured_cb = cb
      ffi.cast "nfq_q_handle*", 0x2000
    nfq_set_mode: (qh, mode, range) -> 0
    nfq_fd: (h) -> 99
    nfq_handle_packet: (h, buf, len) ->
      handled[#handled + 1] = tonumber len
      captured_cb nil, nil, ffi.cast("nfq_data*", fake_hdr), nil if invoke_cb and captured_cb
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
    poll_fds = {}
    handled = {}
    destroyed = 0
    closed = 0
    idle_calls = 0
    captured_cb = nil
    invoke_cb = false
    open_fails = false
    create_queue_fails = false
    verdict_calls = {}

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

  it "timeout de poll (rv=0) → continue après on_idle, puis lit le paquet", ->
    poll_script = {
      { rv: 0 }    -- rien à lire : on_idle, pas de read
      { rv: 1 }    -- paquet prêt
      { rv: 1 }    -- prêt pour la lecture suivante (EOF)
    }
    reads = { { rv: 10 }, { rv: 0 } }
    nfq.run_queue 0, (-> 1), { idle_ms: 10, on_idle: -> idle_calls += 1 }
    assert.equals 3, poll_idx
    assert.equals 3, idle_calls
    assert.equals 2, read_idx
    assert.same { 10 }, handled

  it "applique le GC au démarrage, garde-fou à chaque tour, pas sur timeout", ->
    poll_script = {
      { rv: 0 }    -- timeout : file vide → pas de GC
      { rv: 1 }    -- paquet prêt
      { rv: 1 }    -- prêt pour la lecture suivante (EOF)
    }
    reads = { { rv: 10 }, { rv: 0 } }
    calls = {}
    fake_gc = {
      apply: -> calls[#calls + 1] = "apply"
      guard: -> calls[#calls + 1] = "guard"
      idle: -> calls[#calls + 1] = "idle"
    }
    nfq.run_queue 0, (-> 1), { idle_ms: 10, gc: fake_gc }
    assert.equals "apply", calls[1]
    n_apply, n_guard, n_idle = 0, 0, 0
    for c in *calls
      n_apply += 1 if c == "apply"
      n_guard += 1 if c == "guard"
      n_idle += 1 if c == "idle"
    assert.equals 1, n_apply
    assert.equals 3, n_guard
    assert.equals 1, n_idle

  it "erreur de lecture autre que EINTR/ENOBUFS → sortie (flush final du lot)", ->
    batch = {}
    reads = { { rv: -1, errno: 5 } }   -- EIO
    nfq.run_queue 0, (-> 1), { on_batch_end: -> batch[#batch + 1] = #handled }
    -- Le flush final doit être posé même sur erreur, avant de détruire la queue.
    assert.same { 0 }, batch
    assert.equals 1, destroyed
    assert.equals 1, closed

  it "échec de nfq_open → erreur remontée, aucune queue créée", ->
    open_fails = true
    assert.has_error (-> nfq.run_queue 0, -> 1), "nfq_open() échoué"
    assert.equals 0, destroyed
    assert.equals 0, closed

  it "échec de nfq_create_queue → erreur remontée", ->
    create_queue_fails = true
    assert.has_error (-> nfq.run_queue 7, -> 1), "nfq_create_queue(7) échoué"
    assert.equals 0, destroyed
    assert.equals 0, closed

describe "nfq_loop.run_queue callback C (verdicts et exception)", ->
  teardown ->
    package.loaded["ffi_defs"] = orig_defs
    package.loaded["nfq_loop"] = orig_nfq

  before_each ->
    reads = {}
    read_idx = 0
    poll_script = {}
    poll_idx = 0
    poll_fds = {}
    handled = {}
    destroyed = 0
    closed = 0
    captured_cb = nil
    invoke_cb = true
    open_fails = false
    create_queue_fails = false
    verdict_calls = {}
    fake_hdr.packet_id = 1

  it "pose le verdict renvoyé par le callback avec l'id décodé", ->
    reads = { { rv: 10 }, { rv: 0 } }
    nfq.run_queue 0, -> nfq.NF_ACCEPT
    assert.equals 1, #verdict_calls
    assert.equals 1, verdict_calls[1].id
    assert.equals nfq.NF_ACCEPT, verdict_calls[1].verdict
    assert.equals 0, verdict_calls[1].datalen
    assert.is_true verdict_calls[1].buf_is_nil

  it "VERDICT_DONE ne repose pas de verdict (le callback l'a déjà posé)", ->
    reads = { { rv: 10 }, { rv: 0 } }
    nfq.run_queue 0, -> nfq.VERDICT_DONE
    assert.equals 0, #verdict_calls

  it "exception du callback → NF_DROP (fail-closed), la boucle continue", ->
    reads = { { rv: 10 }, { rv: 0 } }
    nfq.run_queue 0, -> error "boom"
    assert.equals 1, #verdict_calls
    assert.equals nfq.NF_DROP, verdict_calls[1].verdict
    assert.equals 1, closed

  it "ENOBUFS pendant le drain → fin du lot, hook appelé, boucle poursuivie", ->
    batch = {}
    reads = {
      { rv: 10 }                -- lecture bloquante
      { rv: -1, errno: 105 }    -- drain : ENOBUFS
      { rv: 0 }                 -- lecture suivante : EOF
    }
    poll_script = { { rv: 1 } }
    nfq.run_queue 0, (-> nfq.NF_ACCEPT), { on_batch_end: -> batch[#batch + 1] = #handled }
    assert.same { 1, 1 }, batch
    assert.same { 10 }, handled

describe "nfq_loop.run_queue on_batch_end (verdicts différés)", ->
  teardown ->
    package.loaded["ffi_defs"] = orig_defs
    package.loaded["nfq_loop"] = orig_nfq

  before_each ->
    reads = {}
    read_idx = 0
    poll_script = {}
    poll_idx = 0
    poll_fds = {}
    handled = {}
    destroyed = 0
    closed = 0
    idle_calls = 0
    captured_cb = nil
    invoke_cb = false
    open_fails = false
    create_queue_fails = false
    verdict_calls = {}

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

-- ── fd supplémentaires surveillés par le poll (tube question→réponse) ───────
-- Le worker réponses doit drainer son tube IPC même quand SA file NFQUEUE ne
-- reçoit aucun paquet : le fd du tube est passé dans `extra_rfds` et le poll de
-- run_queue le surveille à côté du socket netlink (docs/agents/perf.md §12).
-- Sans ce réveil, le tube se remplit et le worker questions jette les questions.
describe "nfq_loop.run_queue fd supplémentaire (tube question→réponse)", ->
  teardown ->
    package.loaded["ffi_defs"] = orig_defs
    package.loaded["nfq_loop"] = orig_nfq

  before_each ->
    reads = {}
    read_idx = 0
    poll_script = {}
    poll_idx = 0
    poll_fds = {}
    handled = {}
    destroyed = 0
    closed = 0
    idle_calls = 0
    captured_cb = nil
    invoke_cb = false
    open_fails = false
    create_queue_fails = false
    verdict_calls = {}

  it "fd supplémentaire prêt, netlink non prêt → on_extra_ready sans lecture", ->
    extra_calls = 0
    poll_script = {
      { rv: 1, revents: { 0, 1 } }   -- 1er poll : seul le tube est lisible (POLLIN)
      { rv: 1, revents: { 1 } }      -- 2e poll : netlink prêt → lecture (EOF)
    }
    reads = { { rv: 0 } }
    nfq.run_queue 0, (-> 1), {
      extra_rfds: { 42 }
      on_extra_ready: -> extra_calls += 1
    }
    assert.equals 1, extra_calls, "le tube seul réveille la boucle"
    assert.equals 1, read_idx, "aucune lecture netlink sur le seul réveil du tube"
    assert.same { 99, 42 }, poll_fds[1], "le fd du tube est bien dans le poll"
    assert.equals 1, destroyed

  it "POLLHUP sur le fd supplémentaire → surveillance arrêtée, pas de boucle à vide", ->
    extra_calls = 0
    poll_script = {
      { rv: 1, revents: { 0, 0x10 } }   -- tube fermé (écrivain parti)
      { rv: 1, revents: { 1 } }         -- netlink prêt → lecture (EOF)
    }
    reads = { { rv: 0 } }
    nfq.run_queue 0, (-> 1), {
      extra_rfds: { 42 }
      on_extra_ready: -> extra_calls += 1
    }
    assert.equals 0, extra_calls, "aucun drain sans données"
    assert.equals -1, poll_fds[2][2], "le fd mort n'est plus surveillé"
    assert.equals 1, destroyed

-- ── Lecture non bloquante pendant l'attente d'ACK (hook on_batch_end) ────────
-- Pendant `wait_ack`, le worker réponses doit continuer à vider le socket
-- netlink, sinon la file noyau grossit (response_entry_ms, cf.
-- docs/agents/perf.md §16). `nfq_loop` fournit à `on_batch_end` une fonction de
-- lecture bornée, qui ne rappelle JAMAIS `on_batch_end` (pas de réentrance).
describe "nfq_loop.run_queue lecture pendant l'attente (read_batch)", ->
  teardown ->
    package.loaded["ffi_defs"] = orig_defs
    package.loaded["nfq_loop"] = orig_nfq

  before_each ->
    reads = {}
    read_idx = 0
    poll_script = {}
    poll_idx = 0
    poll_fds = {}
    handled = {}
    destroyed = 0
    closed = 0
    idle_calls = 0
    captured_cb = nil
    invoke_cb = false
    open_fails = false
    create_queue_fails = false
    verdict_calls = {}

  it "on_batch_end reçoit une fonction qui lit et dispatche le lot suivant", ->
    seen = {}
    reads = {
      { rv: 10 }                -- lecture bloquante initiale
      { rv: 20 }                -- lue par read_batch
      { rv: 0 }                 -- lecture suivante : EOF
    }
    poll_script = {
      { rv: 0 }                 -- drain du lot : socket vide
      { rv: 1 }                 -- read_batch : paquet prêt
      { rv: 0 }                 -- read_batch : plus rien
    }
    nfq.run_queue 0, (-> 1), {
      on_batch_end: (read_batch) ->
        if read_batch
          before = #handled
          n = read_batch!
          seen[#seen + 1] = { n: n, delta: #handled - before }
        else
          seen[#seen + 1] = { n: 0, delta: 0 }
    }
    assert.same { { n: 1, delta: 1 }, { n: 0, delta: 0 } }, seen
    assert.same { 10, 20 }, handled
    assert.equals 3, poll_idx
    assert.equals 3, read_idx
    assert.equals 1, destroyed

  it "borne la lecture pendant l'attente à MAX_BATCH_PKTS", ->
    first_n = nil
    calls = 0
    reads = {}
    for i = 1, 100
      reads[i] = { rv: 1 }
    reads[101] = { rv: 0 }
    poll_script = { { rv: 0 } }   -- drain initial : socket vide
    for i = 2, 1 + nfq.MAX_BATCH_PKTS
      poll_script[i] = { rv: 1 }  -- polls de read_batch pendant l'attente
    nfq.run_queue 0, (-> 1), {
      on_batch_end: (read_batch) ->
        calls += 1
        if read_batch and not first_n
          first_n = read_batch!
    }
    assert.equals nfq.MAX_BATCH_PKTS, first_n, "le lot lu pendant l'attente est borné"
    assert.equals 100, #handled, "les paquets restants sont lus par la boucle principale"
    assert.equals 101, read_idx

  it "ENOBUFS pendant la lecture de l'attente → arrêt propre de la lecture", ->
    seen = {}
    reads = {
      { rv: 10 }                -- lecture bloquante initiale
      { rv: -1, errno: 105 }    -- read_batch : file noyau pleine
      { rv: 0 }                 -- lecture suivante : EOF
    }
    poll_script = {
      { rv: 0 }                 -- drain du lot : socket vide
      { rv: 1 }                 -- read_batch : prêt (puis ENOBUFS)
    }
    nfq.run_queue 0, (-> 1), {
      on_batch_end: (read_batch) ->
        seen[#seen + 1] = read_batch! if read_batch
    }
    assert.same { 0 }, seen
    assert.same { 10 }, handled
    assert.equals 3, read_idx

  it "read_batch n'est pas réentrant : aucun paquet lu depuis le callback", ->
    rb = nil
    inner = nil
    reads = {
      { rv: 10 }                -- lecture bloquante initiale
      { rv: 20 }                -- lue par read_batch
      { rv: 0 }                 -- lecture suivante : EOF
    }
    poll_script = {
      { rv: 0 }                 -- drain du lot : socket vide
      { rv: 1 }                 -- read_batch : paquet prêt
      { rv: 0 }                 -- read_batch : plus rien
    }
    invoke_cb = true
    cb = (qh, nfad, pkt_id) ->
      inner = rb! if rb
      nfq.NF_ACCEPT
    nfq.run_queue 0, cb, {
      on_batch_end: (read_batch) ->
        if read_batch
          rb = read_batch
          read_batch!
    }
    assert.equals 0, inner, "un appel imbriqué ne lit rien"
    assert.same { 10, 20 }, handled
    assert.equals 3, read_idx, "aucune lecture supplémentaire par l'appel imbriqué"

