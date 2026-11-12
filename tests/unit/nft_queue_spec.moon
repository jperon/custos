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

    line = read_pipe rfd
    fields = split_fields line
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
