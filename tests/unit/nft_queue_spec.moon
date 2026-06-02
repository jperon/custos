ffi = require "ffi"

pcall ffi.cdef, [[
  int pipe2(int pipefd[2], int flags);
  int close(int fd);
  ssize_t read(int fd, void *buf, size_t count);
  ssize_t write(int fd, const void *buf, size_t count);
]]

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
    it "retourne true immédiatement si l'ACK arrive avant le premier timeout", ->
      q = fresh_nft_queue!
      ack_pipe = make_pipe!
      ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd ack_rfd, 0

      -- Écrire l'ACK avant d'appeler wait_ack
      ack_byte = ffi.new "uint8_t[1]"
      ack_byte[0] = 0x01
      ffi.C.write ack_wfd, ack_byte, 1

      ok = q.wait_ack 1, "corr"
      assert.is_true ok
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
        if calls == 2
          ack_byte = ffi.new "uint8_t[1]"
          ack_byte[0] = 0x01
          ffi.C.write ack_wfd, ack_byte, 1

      ok = q.wait_ack 1, "corr", on_wait
      assert.is_true ok
      assert.is_true calls >= 2
      close_pipe ack_pipe

    it "retourne false sans ack_rfd configuré", ->
      q = fresh_nft_queue!
      -- ack_rfd non configuré : wait_ack doit retourner false immédiatement
      ok = q.wait_ack 42, "test-corr"
      assert.is_false ok
