ffi = require "ffi"

pcall ffi.cdef, [[
  int pipe2(int pipefd[2], int flags);
  int close(int fd);
  ssize_t read(int fd, void *buf, size_t count);
  ssize_t write(int fd, const void *buf, size_t count);
]]
-- nft_queue exige struct pollfd et clock_gettime (ffi_defs est remplacé par le
-- stub de busted_setup quand le spec tourne isolément).
pcall ffi.cdef, "struct pollfd { int fd; short events; short revents; };"
pcall ffi.cdef, "int poll(struct pollfd *fds, unsigned long nfds, int timeout);"
pcall ffi.cdef, "int clock_gettime(int clk_id, timespec_t *tp);"

O_NONBLOCK = 2048

make_pipe = ->
  pipefd = ffi.new "int[2]"
  r = ffi.C.pipe2 pipefd, O_NONBLOCK
  assert r == 0, "pipe2 a échoué"
  { pipefd[0], pipefd[1] }

close_pipe = (p) ->
  ffi.C.close p[1]
  ffi.C.close p[2]

fresh_nft_queue = ->
  package.loaded["nft_queue"] = nil
  dofile "lua/nft_queue.lua"

hex = (s) ->
  return "" unless s and #s > 0
  (s\gsub ".", (c) -> string.format "%02x", c\byte!)

-- Format d'ACK : enregistrement de taille fixe (ACK_SIZE octets) portant le
-- plus grand `seq` appliqué par worker_nft pour ce worker.
ACK_SIZE = 8

put_ack = (fd, seq) ->
  v = ffi.new "uint64_t[1]"
  v[0] = seq
  n = ffi.C.write fd, v, ACK_SIZE
  assert n == ACK_SIZE, "écriture ACK incomplète"

-- Écrit les `len` premiers octets de l'enregistrement (simule une lecture
-- partielle côté lecteur, que le format de taille fixe doit reconstituer).
put_ack_partial = (fd, seq, len) ->
  v = ffi.new "uint64_t[1]"
  v[0] = seq
  p = ffi.cast "uint8_t*", v
  n = ffi.C.write fd, p, len
  assert n == len, "écriture ACK partielle incomplète"
  p

read_pipe = (fd) ->
  buf = ffi.new "char[512]"
  n = ffi.C.read fd, buf, 512
  assert n and n > 0, "pipe vide"
  ffi.string buf, n

split_fields = (line) ->
  line = line\gsub "\n+$", ""
  out = {}
  i = 1
  while true
    j = line\find "|", i, true
    if j
      out[#out + 1] = line\sub i, j - 1
      i = j + 1
    else
      out[#out + 1] = line\sub i
      break
  out

describe "nft_queue", ->
  it "cmd_for inclut le timeout demandé", ->
    q = fresh_nft_queue!
    cmd = q.cmd_for "ip4", "192.168.1.42", "10.0.0.1", "dns_rule", "240s"
    assert.is_not_nil cmd
    assert.is_not_nil cmd\find("timeout 240s", 1, true)

  it "add_ip4 propage rule_id + timeout dans la ligne IPC", ->
    q = fresh_nft_queue!
    p = make_pipe!
    rfd, wfd = p[1], p[2]
    q.set_wfd wfd

    ok = q.add_ip4 "192.168.1.42", "10.0.0.1", "dns_workhours", "240s", "corr-123"
    assert.is_true ok
    -- Le producteur tamponne : le lot n'est écrit qu'à sa clôture
    -- (get_last_seq, wait_ack ou send_barrier).
    assert.equals 1, q.get_last_seq!

    line = read_pipe rfd
    fields = split_fields line
    -- Contrat de format : `worker_nft.parse_line` exige EXACTEMENT 9 champs et
    -- rejette la ligne (`field_count`) sinon, donc aucune insertion nft n'est
    -- appliquée. Un helper rendant plusieurs valeurs dans le dernier champ du
    -- constructeur de table ajouterait un 10e champ (régression e2e d-prof).
    assert.equals 9, #fields
    assert.equals "v1", fields[1]
    assert.equals "ip4", fields[2]
    assert.equals "192.168.1.42", fields[3]
    assert.equals "10.0.0.1", fields[4]
    assert.equals hex("dns_workhours"), fields[5]
    assert.equals "240s", fields[6]
    assert.equals hex("corr-123"), fields[9]

    close_pipe p

  describe "wait_ack", ->
    it "retourne true immédiatement si l'ACK du seq attendu arrive avant le premier timeout", ->
      q = fresh_nft_queue!
      ack_pipe = make_pipe!
      ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd ack_rfd, 0

      -- Écrire l'ACK (seq 1) avant d'appeler wait_ack
      put_ack ack_wfd, 1

      ok = q.wait_ack 1, "corr"
      assert.is_true ok
      close_pipe ack_pipe

    it "retourne true quand l'ACK porte un seq supérieur au seq attendu", ->
      q = fresh_nft_queue!
      ack_pipe = make_pipe!
      q.set_ack_rfd ack_pipe[1], 0
      put_ack ack_pipe[2], 7
      assert.is_true q.wait_ack 5, "corr"
      close_pipe ack_pipe

    it "ignore un ACK d'un seq antérieur et expire (false)", ->
      q = fresh_nft_queue!
      ack_pipe = make_pipe!
      q.set_ack_rfd ack_pipe[1], 0
      -- ACK du batch précédent, plus petit que celui attendu.
      put_ack ack_pipe[2], 2
      ok = q.wait_ack 5, "corr"
      assert.is_false ok
      close_pipe ack_pipe

    it "ignore un ACK antérieur puis accepte l'ACK du bon seq", ->
      q = fresh_nft_queue!
      ack_pipe = make_pipe!
      ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd ack_rfd, 0
      put_ack ack_wfd, 2

      calls = 0
      on_wait = ->
        calls += 1
        put_ack ack_wfd, 5 if calls == 2

      ok = q.wait_ack 5, "corr", on_wait
      assert.is_true ok
      -- L'ACK périmé ne doit pas avoir suffi : au moins un tour d'attente.
      assert.is_true calls >= 2
      close_pipe ack_pipe

    it "appelle le callback on_wait entre les polls", ->
      q = fresh_nft_queue!
      ack_pipe = make_pipe!
      ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd ack_rfd, 0

      calls = 0
      -- ACK envoyé après 2 appels du callback
      on_wait = ->
        calls += 1
        put_ack ack_wfd, 1 if calls == 2

      ok = q.wait_ack 1, "corr", on_wait
      assert.is_true ok
      assert.is_true calls >= 2
      close_pipe ack_pipe

    it "reconstitue un ACK lu en deux morceaux", ->
      q = fresh_nft_queue!
      ack_pipe = make_pipe!
      ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd ack_rfd, 0

      p = put_ack_partial ack_wfd, 5, 3
      calls = 0
      on_wait = ->
        calls += 1
        -- Fin de l'enregistrement, après que les 3 premiers octets ont été lus.
        ffi.C.write ack_wfd, p + 3, ACK_SIZE - 3 if calls == 1

      ok = q.wait_ack 5, "corr", on_wait
      assert.is_true ok
      assert.is_true calls >= 1
      close_pipe ack_pipe

    it "retourne false sans ack_rfd configuré", ->
      q = fresh_nft_queue!
      -- ack_rfd non configuré : wait_ack doit retourner false immédiatement
      ok = q.wait_ack 42, "test-corr"
      assert.is_false ok

  describe "drain_ack", ->
    it "vide entièrement un ACK complet", ->
      q = fresh_nft_queue!
      ack_pipe = make_pipe!
      ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd ack_rfd, 0
      put_ack ack_wfd, 3
      q.drain_ack!
      buf = ffi.new "uint8_t[8]"
      assert.equals -1, ffi.C.read ack_rfd, buf, 8   -- EAGAIN : tube vide
      close_pipe ack_pipe

    it "vide aussi un ACK partiel", ->
      q = fresh_nft_queue!
      ack_pipe = make_pipe!
      ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd ack_rfd, 0
      put_ack_partial ack_wfd, 3, 4
      q.drain_ack!
      buf = ffi.new "uint8_t[8]"
      assert.equals -1, ffi.C.read ack_rfd, buf, 8
      close_pipe ack_pipe

describe "nft_queue ACK consommé (last_acked_seq)", ->
  it "drain_ack retient le plus grand seq purgé", ->
    q = fresh_nft_queue!
    ack_pipe = make_pipe!
    q.set_ack_rfd ack_pipe[1], 0
    put_ack ack_pipe[2], 3
    put_ack ack_pipe[2], 7
    q.drain_ack!
    assert.equals 7, q.get_last_acked!
    close_pipe ack_pipe

  it "un ACK purgé par drain_ack ne fait plus expirer wait_ack", ->
    -- Régression mesurée : un lot dont la dernière insertion était suivie d'une
    -- purge d'ACK attendait 150 ms (nft_ack_timeout) un enregistrement qui ne
    -- serait plus jamais réémis.
    q = fresh_nft_queue!
    ack_pipe = make_pipe!
    q.set_ack_rfd ack_pipe[1], 0
    put_ack ack_pipe[2], 42
    q.drain_ack!                    -- l'ACK est consommé par la purge
    assert.is_true q.wait_ack 42, "corr"
    close_pipe ack_pipe

  it "wait_ack retient le seq qu'il a lu", ->
    q = fresh_nft_queue!
    ack_pipe = make_pipe!
    q.set_ack_rfd ack_pipe[1], 0
    put_ack ack_pipe[2], 9
    assert.is_true q.wait_ack 5, "corr"
    assert.equals 9, q.get_last_acked!
    close_pipe ack_pipe

  it "reset_ack_state purge le tube et oublie les ACK résiduels", ->
    q = fresh_nft_queue!
    ack_pipe = make_pipe!
    ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
    q.set_ack_rfd ack_rfd, 0
    put_ack ack_wfd, 100            -- ACK d'un producteur précédent
    q.reset_ack_state!
    assert.equals 0, q.get_last_acked!
    buf = ffi.new "uint8_t[8]"
    assert.equals -1, ffi.C.read ack_rfd, buf, 8   -- tube vide
    close_pipe ack_pipe

  it "un fragment partiel ne met pas à jour last_acked_seq", ->
    q = fresh_nft_queue!
    ack_pipe = make_pipe!
    q.set_ack_rfd ack_pipe[1], 0
    put_ack_partial ack_pipe[2], 5, 4
    q.drain_ack!
    assert.equals 0, q.get_last_acked!
    close_pipe ack_pipe

describe "nft_queue element_spec (regroupement par set)", ->
  it "décrit un élément de set concaténé ip4", ->
    q = fresh_nft_queue!
    spec = q.element_spec "ip4", "10.35.1.2", "93.184.216.1", "r_test", "660s"
    assert.equals "r_test_ip4", spec.set_name
    assert.equals "bridge", spec.family
    assert.equals "10.35.1.2 . 93.184.216.1 timeout 660s", spec.elem

  it "décrit un élément mac6 (clé MAC, valeur IPv6)", ->
    q = fresh_nft_queue!
    spec = q.element_spec "mac6", "d8:d3:85:63:6b:27", "2001:db8::1", "r_test", "2m"
    assert.equals "r_test_mac6", spec.set_name
    assert.equals "d8:d3:85:63:6b:27 . 2001:db8::1 timeout 2m", spec.elem

  it "décrit un élément de set simple (auth/sip) sans valeur", ->
    q = fresh_nft_queue!
    spec = q.element_spec "auth_mac", "d8:d3:85:63:6b:27", "_", "r_test", "90s"
    assert.equals "r_test_auth_mac", spec.set_name
    assert.equals "d8:d3:85:63:6b:27 timeout 90s", spec.elem

  it "set global sip (rule_id vide) reste supporté", ->
    q = fresh_nft_queue!
    spec = q.element_spec "sip4", "1.2.3.4", "1.2.3.4", "", "5m"
    assert.equals "sip_peers", spec.set_name
    assert.equals "1.2.3.4 timeout 5m", spec.elem

  it "rule_id obligatoire : nil si le set ne peut pas être nommé", ->
    q = fresh_nft_queue!
    assert.is_nil q.element_spec "ip4", "10.0.0.1", "1.2.3.4", "", "2m"
    assert.is_nil q.element_spec "inconnu", "a", "b", "r_test", "2m"

  it "timeout invalide → repris de la configuration (comme cmd_for)", ->
    q = fresh_nft_queue!
    spec = q.element_spec "ip4", "10.0.0.1", "1.2.3.4", "r_test", "pas-un-timeout"
    assert.equals "10.0.0.1 . 1.2.3.4 timeout 2m", spec.elem

  it "cmd_lines_for produit exactement la même instruction qu'avant", ->
    q = fresh_nft_queue!
    lines = q.cmd_lines_for "ip4", "10.0.0.1", "1.2.3.4", "r_test", "2m"
    assert.same { "add element bridge dns-filter-bridge r_test_ip4 { 10.0.0.1 . 1.2.3.4 timeout 2m }" }, lines

describe "nft_queue écriture IPC et variantes (branches d'erreur)", ->
  saved_defs = nil
  saved_timeout = nil
  errno_box = nil
  writes = nil
  sleeps = nil
  chunks = nil
  sizes = nil

  fresh_with_libc = (write_fn, sleep_fn) ->
    errno_box = ffi.new "int[1]"
    libc = setmetatable {
      write: write_fn
      __errno_location: -> errno_box
      nanosleep: (req, rem) ->
        sleeps += 1
        sleep_fn req, rem if sleep_fn
        0
    }, { __index: ffi.C }
    package.loaded["ffi_defs"] = { :ffi, :libc }
    package.loaded["nft_queue"] = nil
    dofile "lua/nft_queue.lua"

  setup ->
    saved_defs = package.loaded["ffi_defs"]
    saved_timeout = package.loaded["config"].nft.ip_timeout

  teardown ->
    package.loaded["ffi_defs"] = saved_defs
    package.loaded["config"].nft.ip_timeout = saved_timeout
    package.loaded["nft_queue"] = nil

  before_each ->
    package.loaded["ffi_defs"] = saved_defs
    writes = 0
    sleeps = 0
    errno_box = ffi.new "int[1]"
    chunks = {}
    sizes = {}

  it "sans tube de sortie, l'enqueue retourne false", ->
    q = fresh_nft_queue!
    assert.is_false q.add_ip4 "10.0.0.1", "1.2.3.4", "r_test", "2m"
    assert.is_false q.send_barrier "corr"

  it "une ligne plus grande que PIPE_BUF_SAFE est refusée sans écriture", ->
    wrote = 0
    q = fresh_with_libc ((fd, line, len) ->
      wrote += 1
      len
    ), nil
    q.set_wfd 1
    ok = q.add_ip4 "10.0.0.1", "1.2.3.4", string.rep("r", 600), "2m"
    assert.is_false ok
    -- La ligne refusée n'entre pas dans le tampon : rien à écrire.
    assert.is_nil q.get_last_seq!
    assert.equals 0, wrote

  it "une écriture EAGAIN réessaie après sleep puis réussit", ->
    q = fresh_with_libc ((fd, line, len) ->
      writes += 1
      if writes == 1
        errno_box[0] = 11   -- EAGAIN
        return -1
      len
    ), nil
    q.set_wfd 1
    assert.is_true q.add_ip4 "10.0.0.1", "1.2.3.4", "r_test", "2m"
    assert.equals 1, q.get_last_seq!
    assert.equals 2, writes
    assert.equals 1, sleeps

  it "une erreur d'écriture non EAGAIN abandonne immédiatement", ->
    q = fresh_with_libc ((fd, line, len) ->
      writes += 1
      errno_box[0] = 5   -- EIO
      -1
    ), nil
    q.set_wfd 1
    assert.is_true q.add_ip4 "10.0.0.1", "1.2.3.4", "r_test", "2m"
    assert.is_nil q.get_last_seq!
    assert.equals 1, writes
    assert.equals 0, sleeps

  it "EAGAIN sur toutes les tentatives : aucune écriture, seq nil", ->
    q = fresh_with_libc ((fd, line, len) ->
      writes += 1
      errno_box[0] = 11
      -1
    ), nil
    q.set_wfd 1
    assert.is_true q.add_ip4 "10.0.0.1", "1.2.3.4", "r_test", "2m"
    assert.is_nil q.get_last_seq!
    assert.equals 3, writes
    assert.equals 3, sleeps

  it "send_barrier écrit une ligne barrier et get_last_seq la consomme", ->
    q = fresh_nft_queue!
    p = make_pipe!
    q.set_wfd p[2]
    assert.is_true q.send_barrier "corr-b"
    line = read_pipe p[1]
    assert.truthy line\find "|barrier|", 1, true
    -- Même contrat de format que les lignes d'insertion : 9 champs.
    bfields = split_fields line
    assert.equals 9, #bfields
    assert.equals 1, q.get_last_seq!
    assert.is_nil q.get_last_seq!
    close_pipe p

  it "get_worker_idx reflète set_ack_rfd", ->
    q = fresh_nft_queue!
    assert.is_nil q.get_worker_idx!
    q.set_ack_rfd 7, 3
    assert.equals 3, q.get_worker_idx!

  it "enqueue refuse un tuple incomplet (kind/key/ip manquant)", ->
    q = fresh_nft_queue!
    q.set_wfd 1
    assert.is_false q.add_ip4 nil, "1.2.3.4", "r_test", "2m"
    assert.is_false q.add_ip4 "10.0.0.1", nil, "r_test", "2m"

  it "sanitize_timeout nil/invalide sans repli valide → 2m", ->
    q = fresh_nft_queue!
    assert.equals "2m", q.sanitize_timeout nil
    package.loaded["config"].nft.ip_timeout = "pas-valide"
    q = fresh_nft_queue!
    assert.equals "2m", q.sanitize_timeout "encore-invalide"

  it "sanitize_rule_id tronque au-delà de 126 octets", ->
    q = fresh_nft_queue!
    assert.equals "", q.sanitize_rule_id nil
    long = string.rep "a", 200
    assert.equals 126, #q.sanitize_rule_id long

  it "get_set_name et element_spec couvrent sip6 et auth_ip*", ->
    q = fresh_nft_queue!
    assert.equals "sip_peers6", q.get_set_name "sip6", ""
    assert.equals "r_auth_ip4", q.get_set_name "auth_ip4", "r"
    assert.equals "r_auth_ip6", q.get_set_name "auth_ip6", "r"
    spec = q.element_spec "sip6", "2001:db8::1", "_", "", "2m"
    assert.equals "bridge", spec.family
    assert.equals "2001:db8::1 timeout 2m", spec.elem
    spec = q.element_spec "auth_ip6", "2001:db8::2", "_", "r", "2m"
    assert.equals "r_auth_ip6", spec.set_name

  it "un bloc ACK mixte (complet + fragment) reste non interprété", ->
    q = fresh_nft_queue!
    p = make_pipe!
    put_ack p[2], 5
    put_ack_partial p[2], 9, 4
    q.set_ack_rfd p[1], 0
    q.drain_ack!
    assert.equals 0, q.get_last_acked!
    close_pipe p

  it "enqueue alloue < 300 o par ligne (build_line sans table intermédiaire)", ->
    -- Le hot path enfile 16 lignes par réponse Tailscale (cf. docs/agents/perf.md
    -- §19) : build_line allouait une table de 9 champs + une string concat par
    -- ligne. Seuil calibré sur la mesure GC arrêté dans ce spec (avant correctif 373 o,
    -- après 225 o) avec marge des deux côtés.
    q = fresh_with_libc ((fd, data, len) ->
      writes += 1
      len
    ), nil
    q.set_wfd 1
    -- Échauffement : JIT + cache to_hex, hors mesure.
    for _ = 1, 1000
      q.add_ip4 "10.0.0.1", "1.2.3.4", "r_test", "2m", "corr"
    q.get_last_seq!
    N = 300
    collectgarbage "collect"
    collectgarbage "stop"
    before = collectgarbage "count"
    for _ = 1, N
      -- Pas d'assert dans la boucle : luassert alloue à chaque appel et
      -- fausserait la mesure (constaté : +1100 o/ligne).
      q.add_ip4 "10.0.0.1", "1.2.3.4", "r_test", "2m", "corr"
    after = collectgarbage "count"
    collectgarbage "restart"
    per_line = (after - before) * 1024 / N
    assert.is_true per_line < 300,
      "enqueue alloue #{math.floor per_line} o/ligne (seuil 300)"

  it "un lot de N éléments produit un seul write", ->
    q = fresh_with_libc ((fd, data, len) ->
      writes += 1
      chunks[#chunks + 1] = ffi.string data, len
      sizes[#sizes + 1] = len
      len
    ), nil
    q.set_wfd 1
    assert.is_true q.add_ip4 "10.0.0.1", "1.2.3.4", "r_test", "2m"
    assert.is_true q.add_ip4 "10.0.0.2", "1.2.3.5", "r_test", "2m"
    assert.is_true q.add_ip4 "10.0.0.3", "1.2.3.6", "r_test", "2m"
    -- Tant que le lot n'est pas clos, rien n'est écrit.
    assert.equals 0, writes
    -- La clôture du lot (avant le wait_ack) écrit tout d'un coup.
    assert.equals 3, q.get_last_seq!
    assert.equals 1, writes
    _, n_lines = chunks[1]\gsub "\n", ""
    assert.equals 3, n_lines
    -- seq exact : la dernière ligne du lot porte le seq rendu.
    assert.truthy chunks[1]\find "|3|-1|\n", 1, true

  it "découpe les écritures à PIPE_BUF (4096 octets) sans jamais le dépasser", ->
    q = fresh_with_libc ((fd, data, len) ->
      writes += 1
      chunks[#chunks + 1] = ffi.string data, len
      sizes[#sizes + 1] = len
      len
    ), nil
    q.set_wfd 1
    rule = string.rep "r", 40   -- 80 caractères hexadécimaux par ligne
    for i = 1, 40
      assert.is_true q.add_ip4 "10.0.0.#{i}", "1.2.3.4", rule, "2m"
    assert.equals 40, q.get_last_seq!
    assert.is_true writes >= 2
    for s in *sizes
      assert.is_true s <= 4096
    all = table.concat chunks
    _, n_lines = all\gsub "\n", ""
    assert.equals 40, n_lines

  it "flush le tampon avant wait_ack (aucun ACK attendu pour une ligne non écrite)", ->
    ack_pipe = make_pipe!
    ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
    ack_v = ffi.new "uint64_t[1]"
    q = fresh_with_libc ((fd, data, len) ->
      writes += 1
      -- worker_nft acquitte le plus grand seq qu'il a reçu.
      ack_v[0] = 2
      ffi.C.write ack_wfd, ack_v, ACK_SIZE
      len
    ), nil
    q.set_ack_rfd ack_rfd, 0
    q.set_wfd 1
    q.add_ip4 "10.0.0.1", "1.2.3.4", "r_test", "2m"
    q.add_ip4 "10.0.0.2", "1.2.3.5", "r_test", "2m"
    -- Sans flush préalable, l'ACK ne pourrait jamais arriver (timeout 150 ms).
    assert.is_true q.wait_ack 2, "corr"
    assert.equals 1, writes
    close_pipe ack_pipe

  it "échec d'écriture d'une tranche : get_last_seq ne rend que le seq écrit", ->
    q = fresh_with_libc ((fd, data, len) ->
      writes += 1
      if writes >= 2
        errno_box[0] = 5
        return -1
      len
    ), nil
    q.set_wfd 1
    rule = string.rep "r", 40
    for i = 1, 40
      q.add_ip4 "10.0.0.#{i}", "1.2.3.4", rule, "2m"
    seq = q.get_last_seq!
    assert.equals 2, writes
    assert.is_not_nil seq
    assert.is_true seq > 0 and seq < 40

  it "aucune ligne écrite du lot : get_last_seq est nil", ->
    q = fresh_with_libc ((fd, data, len) ->
      writes += 1
      errno_box[0] = 5
      -1
    ), nil
    q.set_wfd 1
    assert.is_true q.add_ip4 "10.0.0.1", "1.2.3.4", "r_test", "2m"
    assert.is_nil q.get_last_seq!
    assert.equals 1, writes

  it "send_barrier flush le tampon avant d'écrire la barrière", ->
    q = fresh_with_libc ((fd, data, len) ->
      writes += 1
      chunks[#chunks + 1] = ffi.string data, len
      len
    ), nil
    q.set_wfd 1
    q.add_ip4 "10.0.0.1", "1.2.3.4", "r_test", "2m"
    assert.is_true q.send_barrier "corr-b"
    assert.equals 2, writes
    assert.truthy chunks[2]\find "|barrier|", 1, true
    -- seq exact : la barrière porte le seq suivant la ligne tamponnée.
    assert.equals 2, q.get_last_seq!

  it "tube ACK fermé : wait_ack échoue sans boucler sur POLLHUP", ->
    q = fresh_nft_queue!
    p = make_pipe!
    q.set_ack_rfd p[1], 0
    ffi.C.close p[2]   -- plus aucun écrivain
    assert.is_false q.wait_ack 1, "corr"
    ffi.C.close p[1]
