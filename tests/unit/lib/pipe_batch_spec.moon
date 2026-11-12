-- tests/unit/lib/pipe_batch_spec.moon
-- Tampon d'écriture groupée d'un pipe (lib.pipe_batch) : accumulation de
-- messages de taille fixe (pipe learn) ou de lignes (pipe events), écriture en
-- un seul write() par tranche ≤ PIPE_BUF (atomicité vis-à-vis des autres
-- producteurs), ordre préservé, vidage explicite, refus des messages hors
-- format et abandon journalisé en cas d'échec d'écriture.

ffi = require "ffi"

package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

-- libc simulé : chaque write() est enregistré (contenu exact) et son code de
-- retour est scripté. Aucun vrai descripteur n'est ouvert.
writes = {}
write_rc = nil
errno_box = ffi.new "int[1]", 0

fake_libc = {
  write: (fd, buf, n) ->
    n = tonumber n
    if write_rc != nil
      errno_box[0] = write_rc == -1 and 11 or 0   -- EAGAIN
      return write_rc
    data = if type(buf) == "string" then buf else ffi.string buf, n
    writes[#writes + 1] = { fd: fd, :data, n }
    n
  __errno_location: -> errno_box
}

orig_ffi_defs = package.loaded["ffi_defs"]
orig_log    = package.loaded["log"]

logged = {}
log_stub = {
  log_warn: (thunk) -> logged[#logged + 1] = thunk!
}

describe "lib.pipe_batch", ->
  batch = nil

  setup ->
    package.loaded["ffi_defs"] = { :ffi, libc: fake_libc }
    package.loaded["log"] = log_stub
    package.loaded["lib.pipe_batch"] = nil
    batch = require "lib.pipe_batch"

  teardown ->
    package.loaded["ffi_defs"] = orig_ffi_defs
    package.loaded["log"] = orig_log
    package.loaded["lib.pipe_batch"] = nil

  before_each ->
    writes = {}
    logged = {}
    write_rc = nil
    errno_box[0] = 0

  describe "messages de taille fixe", ->
    it "accumule sans écrire, puis vide tout en UN write", ->
      b = batch.new_records 7, 22
      assert.is_true b.add "aaaaaaaaaaaaaaaaaaaaaa"
      assert.is_true b.add "bbbbbbbbbbbbbbbbbbbbbb"
      assert.equals 2, b.pending!
      assert.equals 44, b.bytes!
      assert.equals 0, #writes
      assert.is_true b.flush!
      assert.equals 1, #writes
      assert.equals 7, writes[1].fd
      assert.equals 44, #writes[1].data
      assert.equals "aaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbb", writes[1].data
      assert.equals 0, b.pending!
      assert.equals 0, b.bytes!

    it "refuse un message de taille incorrecte (rien n'est tamponné)", ->
      b = batch.new_records 7, 22
      assert.is_false b.add "court"
      assert.is_false b.add string.rep("x", 23)
      assert.equals 0, b.pending!
      assert.equals 0, #writes

    it "vide la tranche avant de dépasser la capacité (jamais > PIPE_BUF)", ->
      b = batch.new_records 7, 22, 44
      b.add string.rep("a", 22)
      b.add string.rep("b", 22)
      assert.equals 0, #writes
      b.add string.rep("c", 22)
      -- La 3e insertion a d'abord vidé la tranche pleine.
      assert.equals 1, #writes
      assert.equals 44, #writes[1].data
      assert.is_true b.flush!
      assert.equals 2, #writes
      assert.equals 22, #writes[2].data
      assert.equals string.rep("c", 22), writes[2].data

    it "un vidage sur tampon vide n'écrit rien et réussit", ->
      b = batch.new_records 7, 22
      assert.is_true b.flush!
      assert.equals 0, #writes

    it "sans descripteur : add est refusé et flush est un no-op réussi", ->
      b = batch.new_records nil, 22
      assert.is_false b.add string.rep("a", 22)
      assert.is_true b.flush!
      assert.equals 0, #writes

    it "échec d'écriture : flush rend false, journalise et vide le tampon", ->
      b = batch.new_records 7, 22
      b.add string.rep("a", 22)
      write_rc = -1
      assert.is_false b.flush!
      assert.equals 1, #logged
      assert.equals "pipe_batch_write_failed", logged[1].action
      assert.equals 22, logged[1].bytes
      assert.equals 0, b.pending!

    it "arrondit la capacité à un multiple de la taille de message", ->
      -- 45 → 44 : deux messages de 22 o tiennent, le troisième vide la tranche.
      b = batch.new_records 7, 22, 45
      assert.is_true b.add string.rep("a", 22)
      assert.is_true b.add string.rep("b", 22)
      assert.equals 0, #writes
      assert.is_true b.add string.rep("c", 22)
      assert.equals 1, #writes
      assert.equals 44, #writes[1].data
      assert.is_true b.flush!
      assert.equals 2, #writes
      assert.equals 22, #writes[2].data

    it "refuse une taille de message nulle", ->
      assert.is_nil batch.new_records 7, 0
      assert.is_nil batch.new_records 7, nil

  describe "lignes", ->
    it "concatène les lignes accumulées en un seul write, ordre préservé", ->
      b = batch.new_lines 9
      assert.is_true b.add "ligne1\n"
      assert.is_true b.add "ligne2\n"
      assert.equals 2, b.pending!
      assert.equals 14, b.bytes!
      assert.equals 0, #writes
      assert.is_true b.flush!
      assert.equals 1, #writes
      assert.equals 9, writes[1].fd
      assert.equals "ligne1\nligne2\n", writes[1].data

    it "vide la tranche avant de dépasser la capacité", ->
      b = batch.new_lines 9, 10
      b.add "abc\n"
      b.add "de\n"
      assert.equals 0, #writes
      b.add "fgh\n"
      assert.equals 1, #writes
      assert.equals "abc\nde\n", writes[1].data
      assert.is_true b.flush!
      assert.equals 2, #writes
      assert.equals "fgh\n", writes[2].data

    it "refuse une ligne plus grande que la capacité (jamais d'écriture coupée)", ->
      b = batch.new_lines 9, 10
      assert.is_false b.add string.rep("x", 11)
      assert.equals 0, b.pending!
      assert.equals 0, #writes

    it "sans descripteur : add est refusé et flush est un no-op réussi", ->
      b = batch.new_lines nil
      assert.is_false b.add "x\n"
      assert.is_true b.flush!
      assert.equals 0, #writes
