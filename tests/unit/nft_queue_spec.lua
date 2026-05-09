local ffi = require("ffi")
pcall(ffi.cdef, [[  int pipe2(int pipefd[2], int flags);
  int close(int fd);
  ssize_t read(int fd, void *buf, size_t count);
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
    local cmd = q.cmd_for("ip4", "192.168.1.42", "10.0.0.1", "240s")
    assert.is_not_nil(cmd)
    return assert.is_not_nil(cmd:find("timeout 240s", 1, true))
  end)
  return it("add_ip4 propage rule_id + timeout dans la ligne IPC", function()
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
end)
