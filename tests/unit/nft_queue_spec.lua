local ffi = require("ffi")
pcall(ffi.cdef, [[  int pipe2(int pipefd[2], int flags);
  int close(int fd);
  ssize_t read(int fd, void *buf, size_t count);
  ssize_t write(int fd, const void *buf, size_t count);
]])
pcall(ffi.cdef, "struct pollfd { int fd; short events; short revents; };")
pcall(ffi.cdef, "int poll(struct pollfd *fds, unsigned long nfds, int timeout);")
pcall(ffi.cdef, "int clock_gettime(int clk_id, timespec_t *tp);")
local O_NONBLOCK = 2048
local make_pipe
make_pipe = function()
  local pipefd = ffi.new("int[2]")
  local r = ffi.C.pipe2(pipefd, O_NONBLOCK)
  assert(r == 0, "pipe2 a échoué")
  return {
    pipefd[0],
    pipefd[1]
  }
end
local close_pipe
close_pipe = function(p)
  ffi.C.close(p[1])
  return ffi.C.close(p[2])
end
local fresh_nft_queue
fresh_nft_queue = function()
  package.loaded["nft_queue"] = nil
  return dofile("lua/nft_queue.lua")
end
local hex
hex = function(s)
  if not (s and #s > 0) then
    return ""
  end
  return (s:gsub(".", function(c)
    return string.format("%02x", c:byte())
  end))
end
local ACK_SIZE = 8
local put_ack
put_ack = function(fd, seq)
  local v = ffi.new("uint64_t[1]")
  v[0] = seq
  local n = ffi.C.write(fd, v, ACK_SIZE)
  return assert(n == ACK_SIZE, "écriture ACK incomplète")
end
local put_ack_partial
put_ack_partial = function(fd, seq, len)
  local v = ffi.new("uint64_t[1]")
  v[0] = seq
  local p = ffi.cast("uint8_t*", v)
  local n = ffi.C.write(fd, p, len)
  assert(n == len, "écriture ACK partielle incomplète")
  return p
end
local read_pipe
read_pipe = function(fd)
  local buf = ffi.new("char[512]")
  local n = ffi.C.read(fd, buf, 512)
  assert(n and n > 0, "pipe vide")
  return ffi.string(buf, n)
end
local split_fields
split_fields = function(line)
  line = line:gsub("\n+$", "")
  local out = { }
  local i = 1
  while true do
    local j = line:find("|", i, true)
    if j then
      out[#out + 1] = line:sub(i, j - 1)
      i = j + 1
    else
      out[#out + 1] = line:sub(i)
      break
    end
  end
  return out
end
describe("nft_queue", function()
  it("cmd_for inclut le timeout demandé", function()
    local q = fresh_nft_queue()
    local cmd = q.cmd_for("ip4", "192.168.1.42", "10.0.0.1", "dns_rule", "240s")
    assert.is_not_nil(cmd)
    return assert.is_not_nil(cmd:find("timeout 240s", 1, true))
  end)
  it("add_ip4 propage rule_id + timeout dans la ligne IPC", function()
    local q = fresh_nft_queue()
    local p = make_pipe()
    local rfd, wfd = p[1], p[2]
    q.set_wfd(wfd)
    local ok = q.add_ip4("192.168.1.42", "10.0.0.1", "dns_workhours", "240s", "corr-123")
    assert.is_true(ok)
    assert.equals(1, q.get_last_seq())
    local line = read_pipe(rfd)
    local fields = split_fields(line)
    assert.equals(9, #fields)
    assert.equals("v1", fields[1])
    assert.equals("ip4", fields[2])
    assert.equals("192.168.1.42", fields[3])
    assert.equals("10.0.0.1", fields[4])
    assert.equals(hex("dns_workhours"), fields[5])
    assert.equals("240s", fields[6])
    assert.equals(hex("corr-123"), fields[9])
    return close_pipe(p)
  end)
  describe("wait_ack", function()
    it("retourne true immédiatement si l'ACK du seq attendu arrive avant le premier timeout", function()
      local q = fresh_nft_queue()
      local ack_pipe = make_pipe()
      local ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd(ack_rfd, 0)
      put_ack(ack_wfd, 1)
      local ok = q.wait_ack(1, "corr")
      assert.is_true(ok)
      return close_pipe(ack_pipe)
    end)
    it("retourne true quand l'ACK porte un seq supérieur au seq attendu", function()
      local q = fresh_nft_queue()
      local ack_pipe = make_pipe()
      q.set_ack_rfd(ack_pipe[1], 0)
      put_ack(ack_pipe[2], 7)
      assert.is_true(q.wait_ack(5, "corr"))
      return close_pipe(ack_pipe)
    end)
    it("ignore un ACK d'un seq antérieur et expire (false)", function()
      local q = fresh_nft_queue()
      local ack_pipe = make_pipe()
      q.set_ack_rfd(ack_pipe[1], 0)
      put_ack(ack_pipe[2], 2)
      local ok = q.wait_ack(5, "corr")
      assert.is_false(ok)
      return close_pipe(ack_pipe)
    end)
    it("ignore un ACK antérieur puis accepte l'ACK du bon seq", function()
      local q = fresh_nft_queue()
      local ack_pipe = make_pipe()
      local ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd(ack_rfd, 0)
      put_ack(ack_wfd, 2)
      local calls = 0
      local on_wait
      on_wait = function()
        calls = calls + 1
        if calls == 2 then
          return put_ack(ack_wfd, 5)
        end
      end
      local ok = q.wait_ack(5, "corr", on_wait)
      assert.is_true(ok)
      assert.is_true(calls >= 2)
      return close_pipe(ack_pipe)
    end)
    it("appelle le callback on_wait entre les polls", function()
      local q = fresh_nft_queue()
      local ack_pipe = make_pipe()
      local ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd(ack_rfd, 0)
      local calls = 0
      local on_wait
      on_wait = function()
        calls = calls + 1
        if calls == 2 then
          return put_ack(ack_wfd, 1)
        end
      end
      local ok = q.wait_ack(1, "corr", on_wait)
      assert.is_true(ok)
      assert.is_true(calls >= 2)
      return close_pipe(ack_pipe)
    end)
    it("reconstitue un ACK lu en deux morceaux", function()
      local q = fresh_nft_queue()
      local ack_pipe = make_pipe()
      local ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd(ack_rfd, 0)
      local p = put_ack_partial(ack_wfd, 5, 3)
      local calls = 0
      local on_wait
      on_wait = function()
        calls = calls + 1
        if calls == 1 then
          return ffi.C.write(ack_wfd, p + 3, ACK_SIZE - 3)
        end
      end
      local ok = q.wait_ack(5, "corr", on_wait)
      assert.is_true(ok)
      assert.is_true(calls >= 1)
      return close_pipe(ack_pipe)
    end)
    return it("retourne false sans ack_rfd configuré", function()
      local q = fresh_nft_queue()
      local ok = q.wait_ack(42, "test-corr")
      return assert.is_false(ok)
    end)
  end)
  return describe("drain_ack", function()
    it("vide entièrement un ACK complet", function()
      local q = fresh_nft_queue()
      local ack_pipe = make_pipe()
      local ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd(ack_rfd, 0)
      put_ack(ack_wfd, 3)
      q.drain_ack()
      local buf = ffi.new("uint8_t[8]")
      assert.equals(-1, ffi.C.read(ack_rfd, buf, 8))
      return close_pipe(ack_pipe)
    end)
    return it("vide aussi un ACK partiel", function()
      local q = fresh_nft_queue()
      local ack_pipe = make_pipe()
      local ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd(ack_rfd, 0)
      put_ack_partial(ack_wfd, 3, 4)
      q.drain_ack()
      local buf = ffi.new("uint8_t[8]")
      assert.equals(-1, ffi.C.read(ack_rfd, buf, 8))
      return close_pipe(ack_pipe)
    end)
  end)
end)
describe("nft_queue ACK consommé (last_acked_seq)", function()
  it("drain_ack retient le plus grand seq purgé", function()
    local q = fresh_nft_queue()
    local ack_pipe = make_pipe()
    q.set_ack_rfd(ack_pipe[1], 0)
    put_ack(ack_pipe[2], 3)
    put_ack(ack_pipe[2], 7)
    q.drain_ack()
    assert.equals(7, q.get_last_acked())
    return close_pipe(ack_pipe)
  end)
  it("un ACK purgé par drain_ack ne fait plus expirer wait_ack", function()
    local q = fresh_nft_queue()
    local ack_pipe = make_pipe()
    q.set_ack_rfd(ack_pipe[1], 0)
    put_ack(ack_pipe[2], 42)
    q.drain_ack()
    assert.is_true(q.wait_ack(42, "corr"))
    return close_pipe(ack_pipe)
  end)
  it("wait_ack retient le seq qu'il a lu", function()
    local q = fresh_nft_queue()
    local ack_pipe = make_pipe()
    q.set_ack_rfd(ack_pipe[1], 0)
    put_ack(ack_pipe[2], 9)
    assert.is_true(q.wait_ack(5, "corr"))
    assert.equals(9, q.get_last_acked())
    return close_pipe(ack_pipe)
  end)
  it("reset_ack_state purge le tube et oublie les ACK résiduels", function()
    local q = fresh_nft_queue()
    local ack_pipe = make_pipe()
    local ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
    q.set_ack_rfd(ack_rfd, 0)
    put_ack(ack_wfd, 100)
    q.reset_ack_state()
    assert.equals(0, q.get_last_acked())
    local buf = ffi.new("uint8_t[8]")
    assert.equals(-1, ffi.C.read(ack_rfd, buf, 8))
    return close_pipe(ack_pipe)
  end)
  return it("un fragment partiel ne met pas à jour last_acked_seq", function()
    local q = fresh_nft_queue()
    local ack_pipe = make_pipe()
    q.set_ack_rfd(ack_pipe[1], 0)
    put_ack_partial(ack_pipe[2], 5, 4)
    q.drain_ack()
    assert.equals(0, q.get_last_acked())
    return close_pipe(ack_pipe)
  end)
end)
describe("nft_queue element_spec (regroupement par set)", function()
  it("décrit un élément de set concaténé ip4", function()
    local q = fresh_nft_queue()
    local spec = q.element_spec("ip4", "10.35.1.2", "93.184.216.1", "r_test", "660s")
    assert.equals("r_test_ip4", spec.set_name)
    assert.equals("bridge", spec.family)
    return assert.equals("10.35.1.2 . 93.184.216.1 timeout 660s", spec.elem)
  end)
  it("décrit un élément mac6 (clé MAC, valeur IPv6)", function()
    local q = fresh_nft_queue()
    local spec = q.element_spec("mac6", "d8:d3:85:63:6b:27", "2001:db8::1", "r_test", "2m")
    assert.equals("r_test_mac6", spec.set_name)
    return assert.equals("d8:d3:85:63:6b:27 . 2001:db8::1 timeout 2m", spec.elem)
  end)
  it("décrit un élément de set simple (auth/sip) sans valeur", function()
    local q = fresh_nft_queue()
    local spec = q.element_spec("auth_mac", "d8:d3:85:63:6b:27", "_", "r_test", "90s")
    assert.equals("r_test_auth_mac", spec.set_name)
    return assert.equals("d8:d3:85:63:6b:27 timeout 90s", spec.elem)
  end)
  it("set global sip (rule_id vide) reste supporté", function()
    local q = fresh_nft_queue()
    local spec = q.element_spec("sip4", "1.2.3.4", "1.2.3.4", "", "5m")
    assert.equals("sip_peers", spec.set_name)
    return assert.equals("1.2.3.4 timeout 5m", spec.elem)
  end)
  it("rule_id obligatoire : nil si le set ne peut pas être nommé", function()
    local q = fresh_nft_queue()
    assert.is_nil(q.element_spec("ip4", "10.0.0.1", "1.2.3.4", "", "2m"))
    return assert.is_nil(q.element_spec("inconnu", "a", "b", "r_test", "2m"))
  end)
  it("timeout invalide → repris de la configuration (comme cmd_for)", function()
    local q = fresh_nft_queue()
    local spec = q.element_spec("ip4", "10.0.0.1", "1.2.3.4", "r_test", "pas-un-timeout")
    return assert.equals("10.0.0.1 . 1.2.3.4 timeout 2m", spec.elem)
  end)
  return it("cmd_lines_for produit exactement la même instruction qu'avant", function()
    local q = fresh_nft_queue()
    local lines = q.cmd_lines_for("ip4", "10.0.0.1", "1.2.3.4", "r_test", "2m")
    return assert.same({
      "add element bridge dns-filter-bridge r_test_ip4 { 10.0.0.1 . 1.2.3.4 timeout 2m }"
    }, lines)
  end)
end)
return describe("nft_queue écriture IPC et variantes (branches d'erreur)", function()
  local saved_defs = nil
  local saved_timeout = nil
  local errno_box = nil
  local writes = nil
  local sleeps = nil
  local chunks = nil
  local sizes = nil
  local fresh_with_libc
  fresh_with_libc = function(write_fn, sleep_fn)
    errno_box = ffi.new("int[1]")
    local libc = setmetatable({
      write = write_fn,
      __errno_location = function()
        return errno_box
      end,
      nanosleep = function(req, rem)
        sleeps = sleeps + 1
        if sleep_fn then
          sleep_fn(req, rem)
        end
        return 0
      end
    }, {
      __index = ffi.C
    })
    package.loaded["ffi_defs"] = {
      ffi = ffi,
      libc = libc
    }
    package.loaded["nft_queue"] = nil
    return dofile("lua/nft_queue.lua")
  end
  setup(function()
    saved_defs = package.loaded["ffi_defs"]
    saved_timeout = package.loaded["config"].nft.ip_timeout
  end)
  teardown(function()
    package.loaded["ffi_defs"] = saved_defs
    package.loaded["config"].nft.ip_timeout = saved_timeout
    package.loaded["nft_queue"] = nil
  end)
  before_each(function()
    package.loaded["ffi_defs"] = saved_defs
    writes = 0
    sleeps = 0
    errno_box = ffi.new("int[1]")
    chunks = { }
    sizes = { }
  end)
  it("sans tube de sortie, l'enqueue retourne false", function()
    local q = fresh_nft_queue()
    assert.is_false(q.add_ip4("10.0.0.1", "1.2.3.4", "r_test", "2m"))
    return assert.is_false(q.send_barrier("corr"))
  end)
  it("une ligne plus grande que PIPE_BUF_SAFE est refusée sans écriture", function()
    local wrote = 0
    local q = fresh_with_libc((function(fd, line, len)
      wrote = wrote + 1
      return len
    end), nil)
    q.set_wfd(1)
    local ok = q.add_ip4("10.0.0.1", "1.2.3.4", string.rep("r", 600), "2m")
    assert.is_false(ok)
    assert.is_nil(q.get_last_seq())
    return assert.equals(0, wrote)
  end)
  it("une écriture EAGAIN réessaie après sleep puis réussit", function()
    local q = fresh_with_libc((function(fd, line, len)
      writes = writes + 1
      if writes == 1 then
        errno_box[0] = 11
        return -1
      end
      return len
    end), nil)
    q.set_wfd(1)
    assert.is_true(q.add_ip4("10.0.0.1", "1.2.3.4", "r_test", "2m"))
    assert.equals(1, q.get_last_seq())
    assert.equals(2, writes)
    return assert.equals(1, sleeps)
  end)
  it("une erreur d'écriture non EAGAIN abandonne immédiatement", function()
    local q = fresh_with_libc((function(fd, line, len)
      writes = writes + 1
      errno_box[0] = 5
      return -1
    end), nil)
    q.set_wfd(1)
    assert.is_true(q.add_ip4("10.0.0.1", "1.2.3.4", "r_test", "2m"))
    assert.is_nil(q.get_last_seq())
    assert.equals(1, writes)
    return assert.equals(0, sleeps)
  end)
  it("EAGAIN sur toutes les tentatives : aucune écriture, seq nil", function()
    local q = fresh_with_libc((function(fd, line, len)
      writes = writes + 1
      errno_box[0] = 11
      return -1
    end), nil)
    q.set_wfd(1)
    assert.is_true(q.add_ip4("10.0.0.1", "1.2.3.4", "r_test", "2m"))
    assert.is_nil(q.get_last_seq())
    assert.equals(3, writes)
    return assert.equals(3, sleeps)
  end)
  it("send_barrier écrit une ligne barrier et get_last_seq la consomme", function()
    local q = fresh_nft_queue()
    local p = make_pipe()
    q.set_wfd(p[2])
    assert.is_true(q.send_barrier("corr-b"))
    local line = read_pipe(p[1])
    assert.truthy(line:find("|barrier|", 1, true))
    local bfields = split_fields(line)
    assert.equals(9, #bfields)
    assert.equals(1, q.get_last_seq())
    assert.is_nil(q.get_last_seq())
    return close_pipe(p)
  end)
  it("get_worker_idx reflète set_ack_rfd", function()
    local q = fresh_nft_queue()
    assert.is_nil(q.get_worker_idx())
    q.set_ack_rfd(7, 3)
    return assert.equals(3, q.get_worker_idx())
  end)
  it("enqueue refuse un tuple incomplet (kind/key/ip manquant)", function()
    local q = fresh_nft_queue()
    q.set_wfd(1)
    assert.is_false(q.add_ip4(nil, "1.2.3.4", "r_test", "2m"))
    return assert.is_false(q.add_ip4("10.0.0.1", nil, "r_test", "2m"))
  end)
  it("sanitize_timeout nil/invalide sans repli valide → 2m", function()
    local q = fresh_nft_queue()
    assert.equals("2m", q.sanitize_timeout(nil))
    package.loaded["config"].nft.ip_timeout = "pas-valide"
    q = fresh_nft_queue()
    return assert.equals("2m", q.sanitize_timeout("encore-invalide"))
  end)
  it("sanitize_rule_id tronque au-delà de 126 octets", function()
    local q = fresh_nft_queue()
    assert.equals("", q.sanitize_rule_id(nil))
    local long = string.rep("a", 200)
    return assert.equals(126, #q.sanitize_rule_id(long))
  end)
  it("get_set_name et element_spec couvrent sip6 et auth_ip*", function()
    local q = fresh_nft_queue()
    assert.equals("sip_peers6", q.get_set_name("sip6", ""))
    assert.equals("r_auth_ip4", q.get_set_name("auth_ip4", "r"))
    assert.equals("r_auth_ip6", q.get_set_name("auth_ip6", "r"))
    local spec = q.element_spec("sip6", "2001:db8::1", "_", "", "2m")
    assert.equals("bridge", spec.family)
    assert.equals("2001:db8::1 timeout 2m", spec.elem)
    spec = q.element_spec("auth_ip6", "2001:db8::2", "_", "r", "2m")
    return assert.equals("r_auth_ip6", spec.set_name)
  end)
  it("un bloc ACK mixte (complet + fragment) reste non interprété", function()
    local q = fresh_nft_queue()
    local p = make_pipe()
    put_ack(p[2], 5)
    put_ack_partial(p[2], 9, 4)
    q.set_ack_rfd(p[1], 0)
    q.drain_ack()
    assert.equals(0, q.get_last_acked())
    return close_pipe(p)
  end)
  it("enqueue alloue < 300 o par ligne (build_line sans table intermédiaire)", function()
    local q = fresh_with_libc((function(fd, data, len)
      writes = writes + 1
      return len
    end), nil)
    q.set_wfd(1)
    for _ = 1, 1000 do
      q.add_ip4("10.0.0.1", "1.2.3.4", "r_test", "2m", "corr")
    end
    q.get_last_seq()
    local N = 300
    collectgarbage("collect")
    collectgarbage("stop")
    local before = collectgarbage("count")
    for _ = 1, N do
      q.add_ip4("10.0.0.1", "1.2.3.4", "r_test", "2m", "corr")
    end
    local after = collectgarbage("count")
    collectgarbage("restart")
    local per_line = (after - before) * 1024 / N
    return assert.is_true(per_line < 300, "enqueue alloue " .. tostring(math.floor(per_line)) .. " o/ligne (seuil 300)")
  end)
  it("un lot de N éléments produit un seul write", function()
    local q = fresh_with_libc((function(fd, data, len)
      writes = writes + 1
      chunks[#chunks + 1] = ffi.string(data, len)
      sizes[#sizes + 1] = len
      return len
    end), nil)
    q.set_wfd(1)
    assert.is_true(q.add_ip4("10.0.0.1", "1.2.3.4", "r_test", "2m"))
    assert.is_true(q.add_ip4("10.0.0.2", "1.2.3.5", "r_test", "2m"))
    assert.is_true(q.add_ip4("10.0.0.3", "1.2.3.6", "r_test", "2m"))
    assert.equals(0, writes)
    assert.equals(3, q.get_last_seq())
    assert.equals(1, writes)
    local _, n_lines = chunks[1]:gsub("\n", "")
    assert.equals(3, n_lines)
    return assert.truthy(chunks[1]:find("|3|-1|\n", 1, true))
  end)
  it("découpe les écritures à PIPE_BUF (4096 octets) sans jamais le dépasser", function()
    local q = fresh_with_libc((function(fd, data, len)
      writes = writes + 1
      chunks[#chunks + 1] = ffi.string(data, len)
      sizes[#sizes + 1] = len
      return len
    end), nil)
    q.set_wfd(1)
    local rule = string.rep("r", 40)
    for i = 1, 40 do
      assert.is_true(q.add_ip4("10.0.0." .. tostring(i), "1.2.3.4", rule, "2m"))
    end
    assert.equals(40, q.get_last_seq())
    assert.is_true(writes >= 2)
    for _index_0 = 1, #sizes do
      local s = sizes[_index_0]
      assert.is_true(s <= 4096)
    end
    local all = table.concat(chunks)
    local _, n_lines = all:gsub("\n", "")
    return assert.equals(40, n_lines)
  end)
  it("flush le tampon avant wait_ack (aucun ACK attendu pour une ligne non écrite)", function()
    local ack_pipe = make_pipe()
    local ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
    local ack_v = ffi.new("uint64_t[1]")
    local q = fresh_with_libc((function(fd, data, len)
      writes = writes + 1
      ack_v[0] = 2
      ffi.C.write(ack_wfd, ack_v, ACK_SIZE)
      return len
    end), nil)
    q.set_ack_rfd(ack_rfd, 0)
    q.set_wfd(1)
    q.add_ip4("10.0.0.1", "1.2.3.4", "r_test", "2m")
    q.add_ip4("10.0.0.2", "1.2.3.5", "r_test", "2m")
    assert.is_true(q.wait_ack(2, "corr"))
    assert.equals(1, writes)
    return close_pipe(ack_pipe)
  end)
  it("échec d'écriture d'une tranche : get_last_seq ne rend que le seq écrit", function()
    local q = fresh_with_libc((function(fd, data, len)
      writes = writes + 1
      if writes >= 2 then
        errno_box[0] = 5
        return -1
      end
      return len
    end), nil)
    q.set_wfd(1)
    local rule = string.rep("r", 40)
    for i = 1, 40 do
      q.add_ip4("10.0.0." .. tostring(i), "1.2.3.4", rule, "2m")
    end
    local seq = q.get_last_seq()
    assert.equals(2, writes)
    assert.is_not_nil(seq)
    return assert.is_true(seq > 0 and seq < 40)
  end)
  it("aucune ligne écrite du lot : get_last_seq est nil", function()
    local q = fresh_with_libc((function(fd, data, len)
      writes = writes + 1
      errno_box[0] = 5
      return -1
    end), nil)
    q.set_wfd(1)
    assert.is_true(q.add_ip4("10.0.0.1", "1.2.3.4", "r_test", "2m"))
    assert.is_nil(q.get_last_seq())
    return assert.equals(1, writes)
  end)
  it("send_barrier flush le tampon avant d'écrire la barrière", function()
    local q = fresh_with_libc((function(fd, data, len)
      writes = writes + 1
      chunks[#chunks + 1] = ffi.string(data, len)
      return len
    end), nil)
    q.set_wfd(1)
    q.add_ip4("10.0.0.1", "1.2.3.4", "r_test", "2m")
    assert.is_true(q.send_barrier("corr-b"))
    assert.equals(2, writes)
    assert.truthy(chunks[2]:find("|barrier|", 1, true))
    return assert.equals(2, q.get_last_seq())
  end)
  return it("tube ACK fermé : wait_ack échoue sans boucler sur POLLHUP", function()
    local q = fresh_nft_queue()
    local p = make_pipe()
    q.set_ack_rfd(p[1], 0)
    ffi.C.close(p[2])
    assert.is_false(q.wait_ack(1, "corr"))
    return ffi.C.close(p[1])
  end)
end)
