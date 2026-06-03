local ffi = require("ffi")
local bit = require("bit")
for _, c in ipairs({
  "typedef struct { uint8_t _opaque[128]; } sigset_t_custos;",
  [[int pipe2(int pipefd[2], int flags);
    int fcntl(int fd, int cmd, long arg);
    int close(int fd);
    int sigprocmask(int how, const sigset_t_custos *set,
                    sigset_t_custos *oldset);]],
  [[int open(const char *path, int flags, ...);
    int unlink(const char *path);]],
  [[int socket(int domain, int type, int protocol);
    int setsockopt(int fd, int level, int optname,
                   const void *optval, unsigned int optlen);
    int getsockopt(int fd, int level, int optname,
                   void *optval, unsigned int *optlen);]]
}) do
  pcall(ffi.cdef, c)
end
local C = ffi.C
local F_GETFL = 3
local F_SETFL = 4
local probe_fcntl_flag
probe_fcntl_flag = function(candidates)
  local fds = ffi.new("int[2]")
  if C.pipe2(fds, 0) ~= 0 then
    return candidates[1]
  end
  local result = candidates[1]
  for _, v in ipairs(candidates) do
    C.fcntl(fds[0], F_SETFL, v)
    local flags = C.fcntl(fds[0], F_GETFL, 0)
    if bit.band(flags, v) ~= 0 then
      result = v
      break
    end
  end
  C.close(fds[0])
  C.close(fds[1])
  return result
end
local probe_sig_block
probe_sig_block = function()
  local mask = ffi.new("sigset_t_custos")
  ffi.fill(mask, 128, 0)
  for _, v in ipairs({
    0,
    1,
    2,
    3
  }) do
    if C.sigprocmask(v, mask, nil) == 0 then
      return v
    end
  end
  return 0
end
local probe_creat_excl
probe_creat_excl = function()
  local path = "/tmp/.custos_ocr_probe"
  local o_wronly = 1
  local creat, excl = 0x40, 0x80
  C.unlink(path)
  for _, v in ipairs({
    0x40,
    0x100
  }) do
    local fd = C.open(path, bit.bor(o_wronly, v), 0600)
    if fd >= 0 then
      C.close(fd)
      C.unlink(path)
      creat = v
      break
    end
  end
  for _, v in ipairs({
    0x80,
    0x400
  }) do
    local fd1 = C.open(path, bit.bor(o_wronly, creat), 0600)
    if fd1 >= 0 then
      C.close(fd1)
    end
    local fd2 = C.open(path, bit.bor(o_wronly, creat, v), 0600)
    if fd2 < 0 then
      C.unlink(path)
      excl = v
      break
    end
    C.close(fd2)
    C.unlink(path)
  end
  return creat, excl
end
local probe_socket_constants
probe_socket_constants = function()
  local fd = C.socket(2, 2, 0)
  if fd < 0 then
    return 1, 2, 15
  end
  local val = ffi.new("int[1]")
  local optlen = ffi.new("uint32_t[1]")
  local sol, reuseaddr, reuseport = 1, 2, 15
  local found = false
  for _, lv in ipairs({
    1,
    0xFFFF
  }) do
    for _, ra in ipairs({
      2,
      4
    }) do
      val[0] = 1
      C.setsockopt(fd, lv, ra, val, 4)
      val[0] = 0
      optlen[0] = 4
      C.getsockopt(fd, lv, ra, val, optlen)
      if val[0] == 1 then
        sol, reuseaddr = lv, ra
        found = true
        break
      end
    end
    if found then
      break
    end
  end
  for _, rp in ipairs({
    15,
    0x200
  }) do
    val[0] = 1
    C.setsockopt(fd, sol, rp, val, 4)
    val[0] = 0
    optlen[0] = 4
    C.getsockopt(fd, sol, rp, val, optlen)
    if val[0] == 1 then
      reuseport = rp
      break
    end
  end
  C.close(fd)
  return sol, reuseaddr, reuseport
end
local sol, reuseaddr, reuseport = probe_socket_constants()
local o_creat, o_excl = probe_creat_excl()
return {
  O_NONBLOCK = probe_fcntl_flag({
    0x80,
    0x800,
    0x4000
  }),
  O_APPEND = probe_fcntl_flag({
    0x8,
    0x400,
    0x2000
  }),
  O_CREAT = o_creat,
  O_EXCL = o_excl,
  SIG_BLOCK = probe_sig_block(),
  SOL_SOCKET = sol,
  SO_REUSEADDR = reuseaddr,
  SO_REUSEPORT = reuseport
}
