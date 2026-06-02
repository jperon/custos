local ffi = require("ffi")
pcall(ffi.cdef, [[  int pipe2(int pipefd[2], int flags);
  int close(int fd);
  ssize_t read(int fd, void *buf, size_t count);
  ssize_t write(int fd, const void *buf, size_t count);
]])
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
return describe("nft_queue", function()
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
    local line = read_pipe(rfd)
    local fields = split_fields(line)
    assert.equals("v1", fields[1])
    assert.equals("ip4", fields[2])
    assert.equals("192.168.1.42", fields[3])
    assert.equals("10.0.0.1", fields[4])
    assert.equals(hex("dns_workhours"), fields[5])
    assert.equals("240s", fields[6])
    assert.equals(hex("corr-123"), fields[9])
    return close_pipe(p)
  end)
  return describe("wait_ack", function()
    it("retourne true immédiatement si l'ACK arrive avant le premier timeout", function()
      local q = fresh_nft_queue()
      local ack_pipe = make_pipe()
      local ack_rfd, ack_wfd = ack_pipe[1], ack_pipe[2]
      q.set_ack_rfd(ack_rfd, 0)
      local ack_byte = ffi.new("uint8_t[1]")
      ack_byte[0] = 0x01
      ffi.C.write(ack_wfd, ack_byte, 1)
      local ok = q.wait_ack(1, "corr")
      assert.is_true(ok)
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
          local ack_byte = ffi.new("uint8_t[1]")
          ack_byte[0] = 0x01
          return ffi.C.write(ack_wfd, ack_byte, 1)
        end
      end
      local ok = q.wait_ack(1, "corr", on_wait)
      assert.is_true(ok)
      assert.is_true(calls >= 2)
      return close_pipe(ack_pipe)
    end)
    return it("retourne false sans ack_rfd configuré", function()
      local q = fresh_nft_queue()
      local ok = q.wait_ack(42, "test-corr")
      return assert.is_false(ok)
    end)
  end)
end)
