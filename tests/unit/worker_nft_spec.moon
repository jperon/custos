-- tests/unit/worker_nft_spec.moon
-- Tests des helpers purs de worker_nft : parse_line, try_add_pending, flush_batch.
-- La boucle run() (poll/read sur fd) reste couverte par les tests e2e.
-- nft.run_cmd est mocké pour capturer les commandes sans toucher au noyau.

{ :ffi, :libc } = require "ffi_defs"
-- Chaque symbole est déclaré dans un pcall ISOLÉ : une redéfinition (le symbole
-- est souvent déjà déclaré par socket_spec/nft_queue_spec qui tournent avant en
-- suite) échoue sans emporter les autres déclarations. worker_nft (via nft_queue)
-- a besoin de struct pollfd au require ; le test ACK a besoin de pipe2/read.
for decl in *{
  "struct pollfd { int fd; short events; short revents; };"
  "int  poll(struct pollfd *fds, unsigned long nfds, int timeout);"
  "int  pipe2(int pipefd[2], int flags);"
  "int  close(int fd);"
  "long read(int fd, void *buf, unsigned long count);"
  "long write(int fd, const void *buf, unsigned long count);"
}
  pcall ffi.cdef, decl
O_NONBLOCK = 2048

-- Capture des commandes nft émises par flush_batch. On mocke `nft` pour ne pas
-- toucher au noyau ni dépendre de libnftables (stubbée à {} dans busted_setup).
nft_calls = {}
nft_fail_first = false
nft_mock = {
  run_cmd: (cmd, opts) ->
    nft_calls[#nft_calls + 1] = cmd
    if nft_fail_first and #nft_calls == 1
      return false, "syntax error"
    true, nil
  cleanup: ->
}

fresh_worker_nft = ->
  -- Réaffirmer le mock à chaque fois : un autre spec chargé avant peut avoir
  -- tenté de charger la vraie `nft.moon` (échec `nft_ctx_new` sous le stub
  -- libnft={}) et empoisonné package.loaded["nft"]. On l'écrase ici pour que
  -- le require("nft") du worker renvoie le mock.
  package.loaded["nft"] = nft_mock
  package.loaded["worker_nft"] = nil
  dofile "lua/worker_nft.lua"

describe "worker_nft helpers", ->

  local wnft
  before_each ->
    nft_calls = {}
    nft_fail_first = false
    wnft = fresh_worker_nft!

  -- ── parse_line ──────────────────────────────────────────────────────────────
  describe "parse_line", ->

    valid_line = "v1|ip4|10.0.0.1|1.2.3.4||2m|5|0|"

    it "ligne valide → item structuré", ->
      item, err = wnft.parse_line valid_line
      assert.is_nil err
      assert.is_table item
      assert.equals "ip4", item.kind
      assert.equals "10.0.0.1", item.key
      assert.equals "1.2.3.4", item.ip
      assert.equals "2m", item.timeout
      assert.equals 5, item.seq
      assert.equals 0, item.widx

    it "nombre de champs incorrect → nil, field_count", ->
      item, err = wnft.parse_line "v1|ip4|10.0.0.1"
      assert.is_nil item
      assert.equals "field_count", err

    it "version inconnue → nil, version", ->
      item, err = wnft.parse_line "v2|ip4|10.0.0.1|1.2.3.4||2m|5|0|"
      assert.is_nil item
      assert.equals "version", err

    it "tuple invalide (ip4 avec clé non-IPv4) → nil, tuple", ->
      item, err = wnft.parse_line "v1|ip4|pasunip|1.2.3.4||2m|5|0|"
      assert.is_nil item
      assert.equals "tuple", err

    it "seq non numérique → nil, seq", ->
      item, err = wnft.parse_line "v1|ip4|10.0.0.1|1.2.3.4||2m|xx|0|"
      assert.is_nil item
      assert.equals "seq", err

  -- ── try_add_pending (compteur incrémental sans pairs) ─────────────────────────
  describe "try_add_pending", ->

    it "ajoute une nouvelle clé → true", ->
      pending = {}
      item = { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", timeout: "2m" }
      assert.is_true wnft.try_add_pending pending, item

    it "doublon (même kind/key/ip/timeout) → false", ->
      pending = {}
      item = { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", timeout: "2m" }
      assert.is_true wnft.try_add_pending pending, item
      assert.is_false wnft.try_add_pending pending, item

    it "timeout différent → clé distincte → true", ->
      pending = {}
      i1 = { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", timeout: "2m" }
      i2 = { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", timeout: "5m" }
      assert.is_true wnft.try_add_pending pending, i1
      assert.is_true wnft.try_add_pending pending, i2

    it "rule_id différent → clé distincte → true (sets distincts)", ->
      pending = {}
      i1 = { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", timeout: "2m", rule_id: "r_a" }
      i2 = { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", timeout: "2m", rule_id: "r_b" }
      assert.is_true wnft.try_add_pending pending, i1
      assert.is_true wnft.try_add_pending pending, i2
      assert.is_not_nil pending["ip4|10.0.0.1|1.2.3.4|2m|r_a"]
      assert.is_not_nil pending["ip4|10.0.0.1|1.2.3.4|2m|r_b"]

  -- ── flush_batch ───────────────────────────────────────────────────────────────
  describe "flush_batch", ->

    it "émet une commande nft et vide pending", ->
      pending = {}
      pending["ip4|10.0.0.1|1.2.3.4|2m"] = {
        kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", rule_id: "r_test", timeout: "2m"
      }
      wnft.flush_batch pending, {}, {}
      assert.equals 1, #nft_calls
      assert.is_true nft_calls[1]\find("add element", 1, true) != nil
      assert.is_true nft_calls[1]\find("r_test_ip4", 1, true) != nil
      assert.is_true nft_calls[1]\find("10.0.0.1 . 1.2.3.4", 1, true) != nil
      -- pending vidé
      assert.is_nil next pending

    it "ack-only (pending vide, ack_queue non vide) → pas de commande nft", ->
      wnft.flush_batch {}, { { widx: 0, seq: 1 } }, {}
      assert.equals 0, #nft_calls

    it "deux rule_id distincts pour le même couple → deux sets alimentés", ->
      pending = {}
      i1 = { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", timeout: "2m", rule_id: "r_a" }
      i2 = { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", timeout: "2m", rule_id: "r_b" }
      assert.is_true wnft.try_add_pending pending, i1
      assert.is_true wnft.try_add_pending pending, i2
      wnft.flush_batch pending, {}, {}
      assert.equals 1, #nft_calls
      assert.is_true nft_calls[1]\find("r_a_ip4", 1, true) != nil
      assert.is_true nft_calls[1]\find("r_b_ip4", 1, true) != nil

    it "regroupe les éléments d'un même set en UNE instruction", ->
      pending = {}
      for i = 1, 3
        assert.is_true wnft.try_add_pending pending, {
          kind: "ip4", key: "10.0.0.1", ip: "1.2.3.#{i}", timeout: "2m", rule_id: "r_test"
        }
      wnft.flush_batch pending, {}, {}
      assert.equals 1, #nft_calls
      cmd = nft_calls[1]
      assert.equals 1, select(2, cmd\gsub("add element", ""))
      assert.is_not_nil cmd\find("r_test_ip4", 1, true)
      assert.is_not_nil cmd\find("1.2.3.1 timeout 2m", 1, true)
      assert.is_not_nil cmd\find("1.2.3.2 timeout 2m", 1, true)
      assert.is_not_nil cmd\find("1.2.3.3 timeout 2m", 1, true)
      -- Éléments séparés par des virgules dans la même accolade.
      assert.is_nil cmd\find("}\nadd element", 1, true)

    it "sets distincts → une instruction par set, timeouts par élément", ->
      pending = {}
      wnft.try_add_pending pending, { kind: "ip4",  key: "10.0.0.1", ip: "1.2.3.4", timeout: "2m",  rule_id: "r_test" }
      wnft.try_add_pending pending, { kind: "ip4",  key: "10.0.0.1", ip: "1.2.3.5", timeout: "10s", rule_id: "r_test" }
      wnft.try_add_pending pending, { kind: "mac4", key: "d8:d3:85:63:6b:27", ip: "1.2.3.4", timeout: "2m", rule_id: "r_test" }
      wnft.flush_batch pending, {}, {}
      assert.equals 1, #nft_calls
      cmd = nft_calls[1]
      assert.equals 2, select(2, cmd\gsub("add element", ""))
      assert.is_not_nil cmd\find("r_test_ip4", 1, true)
      assert.is_not_nil cmd\find("r_test_mac4", 1, true)
      assert.is_not_nil cmd\find("1.2.3.5 timeout 10s", 1, true)

    it "kind inconnu ignoré (aucune commande, ACK quand même)", ->
      pending = {}
      pending["x"] = { kind: "inconnu", key: "a", ip: "b", timeout: "2m", rule_id: "r_test" }
      wnft.flush_batch pending, {}, {}
      assert.equals 0, #nft_calls

    it "échec du lot groupé → repli élément par élément", ->
      nft_fail_first = true
      pending = {}
      for i = 1, 2
        assert.is_true wnft.try_add_pending pending, {
          kind: "ip4", key: "10.0.0.1", ip: "1.2.3.#{i}", timeout: "2m", rule_id: "r_test"
        }
      wnft.flush_batch pending, {}, {}
      -- 1 commande groupée (échec) + 2 commandes élément par élément.
      assert.equals 3, #nft_calls
      assert.equals 1, select(2, nft_calls[1]\gsub("add element", ""))   -- groupée
      -- Repli : une instruction par élément (ordre de `pairs` non garanti).
      singles = nft_calls[2] .. "\n" .. nft_calls[3]
      assert.equals 1, select(2, nft_calls[2]\gsub("add element", ""))
      assert.equals 1, select(2, nft_calls[3]\gsub("add element", ""))
      assert.is_not_nil singles\find("1.2.3.1 timeout 2m", 1, true)
      assert.is_not_nil singles\find("1.2.3.2 timeout 2m", 1, true)

    it "envoie un ACK de taille fixe portant le seq sur le fd du worker concerné", ->
      pipefd = ffi.new "int[2]"
      assert.equals 0, libc.pipe2 pipefd, O_NONBLOCK
      -- ack_wfds indexé par worker : widx 0 → slot 1 = extrémité d'écriture.
      wnft.flush_batch {}, { { widx: 0, seq: 1 } }, { pipefd[1] }
      ack = ffi.new "uint64_t[1]"
      n = libc.read pipefd[0], ack, 8
      -- Un seul enregistrement (8 octets), portant le seq acquitté.
      assert.equals 8, tonumber n
      assert.equals 1, tonumber ack[0]
      libc.close pipefd[0]
      libc.close pipefd[1]

    it "un seul ACK par worker, portant le plus grand seq du batch", ->
      pipefd = ffi.new "int[2]"
      assert.equals 0, libc.pipe2 pipefd, O_NONBLOCK
      wnft.flush_batch {}, { { widx: 0, seq: 3 }, { widx: 0, seq: 9 } }, { pipefd[1] }
      ack = ffi.new "uint64_t[1]"
      n = libc.read pipefd[0], ack, 8
      assert.equals 8, tonumber n
      assert.equals 9, tonumber ack[0]
      -- Pas de second ACK : l'enregistrement est unique.
      assert.equals -1, libc.read pipefd[0], ack, 8
      libc.close pipefd[0]
      libc.close pipefd[1]

  -- ── run() de bout en bout (boucle poll/drain/flush jusqu'à EOF) ──────────────
  describe "run", ->

    it "draine le pipe, émet les commandes nft et l'ACK, puis sort sur EOF", ->
      -- Pipe d'entrée : on y écrit des lignes, le worker lit inp[0].
      inp = ffi.new "int[2]"
      assert.equals 0, libc.pipe2 inp, O_NONBLOCK
      -- Pipe d'ACK : le worker écrit sur ack[1], on relit sur ack[0].
      ack = ffi.new "int[2]"
      assert.equals 0, libc.pipe2 ack, O_NONBLOCK

      hex = (s) -> (s\gsub ".", (c) -> string.format "%02x", c\byte!)
      rid = hex "r_test"
      l1 = "v1|ip4|10.0.0.1|1.2.3.4|#{rid}|2m|1|0|\n"
      l2 = "v1|ip4|10.0.0.2|5.6.7.8|#{rid}|2m|2|0|\n"
      data = l1 .. l2
      libc.write inp[1], data, #data
      libc.close inp[1]   -- ferme l'écriture → le worker verra EOF après drain

      -- ack_wfds : worker_idx 0 → slot 1 = extrémité d'écriture du pipe d'ACK.
      wnft.run inp[0], { ack[1] }
      libc.close inp[0]

      -- Deux insertions distinctes émises.
      assert.equals 1, #nft_calls
      assert.is_true nft_calls[1]\find("10.0.0.1 . 1.2.3.4", 1, true) != nil
      assert.is_true nft_calls[1]\find("10.0.0.2 . 5.6.7.8", 1, true) != nil

      -- Un ACK pour le worker 0, portant le plus grand seq du batch.
      ack_val = ffi.new "uint64_t[1]"
      n = libc.read ack[0], ack_val, 8
      libc.close ack[0]
      libc.close ack[1]
      assert.equals 8, tonumber n
      assert.equals 2, tonumber ack_val[0]

    it "plafonne le batch à MAX_BATCH (65 items distincts → 2 flushes, 2 ACK séquencés)", ->
      inp = ffi.new "int[2]"
      assert.equals 0, libc.pipe2 inp, O_NONBLOCK
      ack = ffi.new "int[2]"
      assert.equals 0, libc.pipe2 ack, O_NONBLOCK
      hex = (s) -> (s\gsub ".", (c) -> string.format "%02x", c\byte!)
      rid = hex "r_test"
      parts = {}
      for i = 1, 65
        a = i % 256
        b = math.floor(i / 256) % 256
        parts[#parts + 1] = "v1|ip4|10.0.#{b}.#{a}|1.2.3.4|#{rid}|2m|#{i}|0|\n"
      data = table.concat parts
      libc.write inp[1], data, #data
      libc.close inp[1]
      wnft.run inp[0], { ack[1] }
      libc.close inp[0]
      -- 65 items > MAX_BATCH (64) ⇒ le drain est tronqué ⇒ deux flushes et
      -- donc deux ACK : le premier pour le batch plein (seq 64), le second pour
      -- le reliquat (seq 65, dernier seq enfilé).
      a1 = ffi.new "uint64_t[1]"
      a2 = ffi.new "uint64_t[1]"
      n1 = libc.read ack[0], a1, 8
      n2 = libc.read ack[0], a2, 8
      libc.close ack[0]
      libc.close ack[1]
      -- 65 items > MAX_BATCH (64) ⇒ au moins deux flushes.
      assert.is_true #nft_calls >= 2
      assert.equals 8, tonumber n1
      assert.equals 64, tonumber a1[0]
      assert.equals 8, tonumber n2
      assert.equals 65, tonumber a2[0]
