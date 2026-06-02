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
nft_mock = {
  run_cmd: (cmd, opts) ->
    nft_calls[#nft_calls + 1] = cmd
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

    it "envoie un ACK sur le fd du worker concerné", ->
      pipefd = ffi.new "int[2]"
      assert.equals 0, libc.pipe2 pipefd, O_NONBLOCK
      -- ack_wfds indexé par worker : widx 0 → slot 1 = extrémité d'écriture.
      wnft.flush_batch {}, { { widx: 0, seq: 1 } }, { pipefd[1] }
      buf = ffi.new "uint8_t[8]"
      n = libc.read pipefd[0], buf, 8
      libc.close pipefd[0]
      libc.close pipefd[1]
      assert.equals 1, tonumber n        -- un seul octet d'ACK
      assert.equals 0x01, buf[0]

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

      -- Au moins un ACK reçu pour le worker 0.
      buf = ffi.new "uint8_t[8]"
      n = libc.read ack[0], buf, 8
      libc.close ack[0]
      libc.close ack[1]
      assert.is_true (tonumber(n) or 0) >= 1
      assert.equals 0x01, buf[0]

    it "plafonne le batch à MAX_BATCH (65 items distincts → ≥2 flushes)", ->
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
      libc.close ack[0]
      libc.close ack[1]
      -- 65 items > MAX_BATCH (64) ⇒ le drain est tronqué ⇒ au moins deux flushes.
      assert.is_true #nft_calls >= 2
