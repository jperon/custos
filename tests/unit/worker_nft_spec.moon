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
nft_fail_all = false
nft_mock = {
  run_cmd: (cmd, opts) ->
    nft_calls[#nft_calls + 1] = cmd
    if nft_fail_all
      return false, "syntax error"
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
    nft_fail_all = false
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

describe "worker_nft branches d'erreur et build_batch", ->
  local wnft
  before_each ->
    nft_calls = {}
    nft_fail_first = false
    nft_fail_all = false
    wnft = fresh_worker_nft!

  it "parse_line valide chaque type de tuple", ->
    hex = (s) -> (s\gsub ".", (c) -> string.format "%02x", c\byte!)
    rid = hex "r_test"
    lines = {
      "v1|ip6|2001:db8::1|2001:db8::2|#{rid}|2m|1|0|"
      "v1|mac4|d8:d3:85:63:6b:27|1.2.3.4|#{rid}|2m|1|0|"
      "v1|mac6|d8:d3:85:63:6b:27|2001:db8::2|#{rid}|2m|1|0|"
      "v1|sip4|1.2.3.4|1.2.3.4|#{rid}|2m|1|0|"
      "v1|sip6|2001:db8::1|_|#{rid}|2m|1|0|"
    }
    for line in *lines
      item, err = wnft.parse_line line
      assert.is_nil err, "ligne refusée : #{line}"
      assert.is_table item

  it "parse_line refuse kind inconnu, hex invalide et worker_idx absent", ->
    item, err = wnft.parse_line "v1|inconnu|a|b||2m|1|0|"
    assert.is_nil item
    assert.equals "tuple", err
    item, err = wnft.parse_line "v1|ip4|10.0.0.1|1.2.3.4|zz|2m|1|0|"
    assert.is_nil item
    assert.truthy err\match "^rule_id_"
    item, err = wnft.parse_line "v1|ip4|10.0.0.1|1.2.3.4||2m|1|xx|"
    assert.is_nil item
    assert.equals "worker_idx", err
    item, err = wnft.parse_line "v1|ip4|10.0.0.1|1.2.3.4||2m|1|0|zz"
    assert.is_nil item
    assert.truthy err\match "^corr_"

  it "build_batch : pending vide → aucune commande", ->
    batch = wnft.build_batch {}
    assert.equals 0, batch.count
    assert.equals 0, #batch.cmds
    assert.equals 0, #batch.singles

  it "build_batch : regroupe par set et ignore les éléments non nommables", ->
    pending = {}
    wnft.try_add_pending pending, { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", timeout: "2m", rule_id: "r_a" }
    wnft.try_add_pending pending, { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.5", timeout: "2m", rule_id: "r_a" }
    wnft.try_add_pending pending, { kind: "mac4", key: "d8:d3:85:63:6b:27", ip: "1.2.3.4", timeout: "2m", rule_id: "r_b" }
    pending["invalide"] = { kind: "inconnu", key: "a", ip: "b", timeout: "2m", rule_id: "r_a" }
    batch = wnft.build_batch pending
    assert.equals 3, batch.count
    assert.equals 2, #batch.cmds
    assert.equals 3, #batch.singles

  it "send_ack ignore un worker_idx négatif (pas de fd destinataire)", ->
    wnft.flush_batch {}, { { widx: -1, seq: 2 } }, {}
    assert.equals 0, #nft_calls

  it "un échec des reprises élément par élément est journalisé", ->
    nft_fail_all = true
    pending = {}
    wnft.try_add_pending pending, { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", timeout: "2m", rule_id: "r_test" }
    wnft.try_add_pending pending, { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.5", timeout: "2m", rule_id: "r_test" }
    wnft.flush_batch pending, {}, {}
    -- 1 commande groupée + 2 replis, tous en échec.
    assert.equals 3, #nft_calls

  it "flush_batch journalise la branche DEBUG rule_11 sans erreur", ->
    stub = {
      log_info: -> nil
      log_warn: -> nil
      log_debug: -> nil
      set_action_prefix: -> nil
      level_enabled: -> true
    }
    saved = package.loaded["log"]
    package.loaded["log"] = stub
    package.loaded["worker_nft"] = nil
    w = dofile "lua/worker_nft.lua"
    pending = {}
    w.try_add_pending pending, { kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", timeout: "2m", rule_id: "rule_11" }
    w.flush_batch pending, {}, {}
    package.loaded["log"] = saved
    assert.equals 1, #nft_calls

  it "run ignore les lignes vides et journalise une ligne invalide", ->
    inp = ffi.new "int[2]"
    assert.equals 0, libc.pipe2 inp, O_NONBLOCK
    data = "\n\nv1|inconnu|a|b||2m|1|0|\n"
    libc.write inp[1], data, #data
    libc.close inp[1]
    assert.is_nil wnft.run inp[0], {}
    libc.close inp[0]
    assert.equals 0, #nft_calls

  it "run vide un fragment géant sans newline au lieu de le laisser croître", ->
    inp = ffi.new "int[2]"
    assert.equals 0, libc.pipe2 inp, O_NONBLOCK
    data = string.rep "x", 5000
    libc.write inp[1], data, #data
    libc.close inp[1]
    assert.is_nil wnft.run inp[0], {}
    libc.close inp[0]
    assert.equals 0, #nft_calls

-- ── Cache d'upsert : saut des ré-insertions récentes ──────────────────────────
-- Même élément (famille/table/set/élément) réinséré à chaque réponse DNS pour
-- rafraîchir son timeout : docs/agents/perf.md §16.3 (delta de sets nul,
-- worker nft 50-65 % d'un vCPU).
describe "worker_nft cache d'upsert", ->
  local wnft
  before_each ->
    nft_calls = {}
    nft_fail_first = false
    nft_fail_all = false
    wnft = fresh_worker_nft!

  hex = (s) -> (s\gsub ".", (c) -> string.format "%02x", c\byte!)

  mk_item = (over) ->
    over = over or {}
    item = {
      kind: "ip4", key: "10.0.0.1", ip: "1.2.3.4", rule_id: "r_test"
      timeout: "2m", has_timeout: true
    }
    for k, v in pairs over
      item[k] = v
    item

  -- Passe l'item dans un lot appliqué avec succès : le cache doit alors
  -- retenir l'instant + le timeout de cette insertion.
  apply_item = (cache, item) ->
    pending = {}
    assert.is_true wnft.try_add_pending pending, item, cache
    wnft.flush_batch pending, {}, {}, cache
    item

  describe "parse_line et timeouts", ->

    it "ligne avec timeout → has_timeout true", ->
      item, err = wnft.parse_line "v1|ip4|10.0.0.1|1.2.3.4||2m|5|0|"
      assert.is_nil err
      assert.is_true item.has_timeout

    it "ligne sans timeout → has_timeout false (timeout de repli appliqué)", ->
      item, err = wnft.parse_line "v1|ip4|10.0.0.1|1.2.3.4|||5|0|"
      assert.is_nil err
      assert.is_false item.has_timeout
      assert.equals "2m", item.timeout

    it "timeout_to_seconds convertit les formes nft", ->
      assert.equals 120, wnft.timeout_to_seconds "2m"
      assert.equals 30, wnft.timeout_to_seconds "30s"
      assert.equals 3600, wnft.timeout_to_seconds "1h"
      assert.equals 86400, wnft.timeout_to_seconds "1d"
      assert.equals 604800, wnft.timeout_to_seconds "1w"
      assert.equals 60, wnft.timeout_to_seconds "60"
      assert.is_nil wnft.timeout_to_seconds "abc"
      assert.is_nil wnft.timeout_to_seconds nil

  describe "décision de saut", ->

    it "saut dans la fenêtre : non ajoutée, skipped incrémenté", ->
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, mk_item!
      pending = {}
      -- Fenêtre = min(120/10, 5) = 5 s ; âge 0 s → saut.
      assert.is_false wnft.try_add_pending pending, mk_item!, cache
      assert.is_nil next pending
      assert.equals 1, cache.skipped
      assert.equals 1, cache.size

    it "âge ≥ fenêtre → réinsérée (rafraîchissement réel)", ->
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, mk_item!
      cache.now = -> 105
      pending = {}
      assert.is_true wnft.try_add_pending pending, mk_item!, cache
      assert.is_not_nil next pending
      assert.equals 0, cache.skipped

    it "timeout plus long que la fenêtre → réinsérée (pas de raccourcissement)", ->
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, mk_item!            -- 2m = 120 s, t = 100
      cache.now = -> 101
      pending = {}
      -- 300 s > 120 + min(300/10, 5)=5 → la vie de l'élément serait
      -- raccourcie si l'on sautait.
      assert.is_true wnft.try_add_pending pending, (mk_item { timeout: "5m" }), cache

    it "timeout légèrement allongé mais dans la fenêtre → saut", ->
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, mk_item { timeout: "100s" }
      cache.now = -> 101
      pending = {}
      -- 103 ≤ 100 + min(103/10, 5)=5 → saut autorisé.
      assert.is_false wnft.try_add_pending pending, (mk_item { timeout: "103s" }), cache
      assert.equals 1, cache.skipped

    it "sans timeout dans la ligne → jamais de saut", ->
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, mk_item!
      cache.now = -> 100
      pending = {}
      assert.is_true wnft.try_add_pending pending, (mk_item { has_timeout: false }), cache
      assert.is_not_nil next pending

    it "item sans timeout ne s'inscrit pas comme référence de saut", ->
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, mk_item { has_timeout: false, timeout: "bizarre" }
      -- timeout invalide → pas de timeout_s → l'entrée ne peut pas servir de
      -- référence de saut, même dans la fenêtre.
      pending = {}
      assert.is_true wnft.try_add_pending pending, (mk_item { has_timeout: false, timeout: "bizarre" }), cache
      pending2 = {}
      assert.is_true wnft.try_add_pending pending2, mk_item!, cache

  describe "invalidation", ->

    it "échec de transaction nft → entrées du lot invalidées, plus de saut", ->
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, mk_item!
      key = wnft.cache_key_of mk_item!
      assert.is_not_nil cache.entries[key]
      -- Lot manuel portant la même clé (contourne le saut) qui échoue.
      nft_fail_all = true
      pending = {}
      pending["manuel"] = mk_item!
      wnft.flush_batch pending, {}, {}, cache
      assert.is_nil cache.entries[key]
      assert.equals 0, cache.size
      -- La ligne suivante, pourtant dans la fenêtre, n'est plus sautée.
      nft_fail_all = false
      pending2 = {}
      assert.is_true wnft.try_add_pending pending2, mk_item!, cache

    it "repli élément par élément réussi → l'élément est réenregistré", ->
      nft_fail_first = true
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, mk_item!
      assert.equals 2, #nft_calls          -- groupée (échec) + élément seul
      assert.is_not_nil cache.entries[wnft.cache_key_of mk_item!]

    it "cache_clear vide le cache (invalidation globale)", ->
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, mk_item!
      assert.equals 1, cache.size
      wnft.cache_clear cache
      assert.equals 0, cache.size
      assert.is_nil next cache.entries
      pending = {}
      assert.is_true wnft.try_add_pending pending, mk_item!, cache

    it "un ajout réussi après invalidation re-enregistre l'entrée", ->
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, mk_item!
      wnft.cache_clear cache
      apply_item cache, mk_item!
      assert.equals 1, cache.size
      assert.is_not_nil cache.entries[wnft.cache_key_of mk_item!]

  describe "ACK des lignes sautées", ->

    it "ligne sautée : aucune commande nft, ACK au seq de la ligne", ->
      inp = ffi.new "int[2]"
      assert.equals 0, libc.pipe2 inp, O_NONBLOCK
      ack = ffi.new "int[2]"
      assert.equals 0, libc.pipe2 ack, O_NONBLOCK
      cache = wnft.new_cache!
      wnft.cache_put cache, wnft.cache_key_of(mk_item!), 120
      rid = hex "r_test"
      line = "v1|ip4|10.0.0.1|1.2.3.4|#{rid}|2m|7|0|\n"
      libc.write inp[1], line, #line
      libc.close inp[1]
      wnft.run inp[0], { ack[1] }, cache
      libc.close inp[0]
      -- Sauté → zéro transaction nft, mais le seq 7 est bien acquitté.
      assert.equals 0, #nft_calls
      ack_val = ffi.new "uint64_t[1]"
      n = libc.read ack[0], ack_val, 8
      assert.equals 8, tonumber n
      assert.equals 7, tonumber ack_val[0]
      libc.close ack[0]
      libc.close ack[1]

    it "ligne hors fenêtre → insérée puis ACKée", ->
      inp = ffi.new "int[2]"
      assert.equals 0, libc.pipe2 inp, O_NONBLOCK
      ack = ffi.new "int[2]"
      assert.equals 0, libc.pipe2 ack, O_NONBLOCK
      cache = wnft.new_cache!
      key = wnft.cache_key_of mk_item!
      wnft.cache_put cache, key, 120
      cache.entries[key].t = cache.now! - 60   -- hors fenêtre (≥ 5 s)
      rid = hex "r_test"
      line = "v1|ip4|10.0.0.1|1.2.3.4|#{rid}|2m|7|0|\n"
      libc.write inp[1], line, #line
      libc.close inp[1]
      wnft.run inp[0], { ack[1] }, cache
      libc.close inp[0]
      assert.equals 1, #nft_calls
      ack_val = ffi.new "uint64_t[1]"
      n = libc.read ack[0], ack_val, 8
      assert.equals 8, tonumber n
      assert.equals 7, tonumber ack_val[0]
      libc.close ack[0]
      libc.close ack[1]

  describe "borne mémoire", ->

    it "la taille ne dépasse jamais `max` (évitcion des plus anciennes)", ->
      cache = wnft.new_cache { max: 4, now: -> 100 }
      for i = 1, 10
        wnft.cache_put cache, "k#{i}", 120
        assert.is_true cache.size <= 4, "size=#{cache.size} > max"
      assert.equals 4, cache.size
      assert.is_true cache.evicted >= 6

    it "les entrées plus vieilles que la fenêtre sont purgées", ->
      cache = wnft.new_cache { max: 1, now: -> 100 }
      wnft.cache_put cache, "ancienne", 120
      cache.now = -> 110          -- 10 s > fenêtre max (5 s) : inutile au saut
      wnft.cache_put cache, "fraiche", 120
      assert.is_nil cache.entries["ancienne"]
      assert.equals 1, cache.size

  -- ── Exclusions : kinds auth_* et sets vidés/supprimés hors worker_nft ───────
  -- Un set qu'un AUTRE processus vide ou supprime (logout/bye/expiration,
  -- rechargement de liste) invaliderait silencieusement une entrée du cache :
  -- la réinsertion suivante serait sautée alors que l'élément n'existe plus.
  describe "exclusions", ->

    it "kind auth : ligne répétée jamais sautée, jamais enregistrée", ->
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, (mk_item { kind: "auth_ip4", ip: "_" })
      -- Ni enregistrement : l'insertion ne doit pas servir de référence.
      assert.equals 0, cache.size
      assert.is_nil next cache.entries
      -- Ni saut : la seconde ligne (même instant) entre dans pending.
      pending = {}
      assert.is_true wnft.try_add_pending pending, (mk_item { kind: "auth_ip4", ip: "_" }), cache
      assert.is_not_nil next pending
      assert.equals 0, cache.skipped

    it "kinds auth_mac et auth_ip6 exclus également", ->
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, (mk_item { kind: "auth_mac", key: "d8:d3:85:63:6b:27", ip: "_" })
      apply_item cache, (mk_item { kind: "auth_ip6", key: "fd00::7", ip: "_" })
      assert.equals 0, cache.size
      pending = {}
      assert.is_true wnft.try_add_pending pending, (mk_item { kind: "auth_mac", key: "d8:d3:85:63:6b:27", ip: "_" }), cache
      assert.is_true wnft.try_add_pending pending, (mk_item { kind: "auth_ip6", key: "fd00::7", ip: "_" }), cache
      assert.equals 0, cache.skipped

    it "cache_key_of : nil pour un kind auth, clé pour un kind DNS", ->
      assert.is_nil wnft.cache_key_of(mk_item { kind: "auth_ip4", ip: "_" })
      assert.is_not_nil wnft.cache_key_of(mk_item!)

    it "contrôle : une ligne DNS répétée est toujours sautée dans la fenêtre", ->
      cache = wnft.new_cache { now: -> 100 }
      apply_item cache, mk_item!
      pending = {}
      assert.is_false wnft.try_add_pending pending, mk_item!, cache
      assert.is_nil next pending
      assert.equals 1, cache.skipped
      assert.equals 1, cache.size

    it "cacheable_set : les sets vidés/supprimés hors worker_nft sont exclus", ->
      for s in *{ "authenticated_ips", "authenticated_ips6", "authenticated_macs",
                  "ip4_dest_whitelist", "ip6_dest_whitelist" }
        assert.is_false wnft.cacheable_set(s), "exclu attendu : #{s}"
      assert.is_true wnft.cacheable_set "r_test_ip4"
      assert.is_true wnft.cacheable_set "sip_peers"
      assert.is_true wnft.cacheable_set nil
