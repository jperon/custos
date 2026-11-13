local ffi = require("ffi")
local bit = require("bit")
local libc
libc = require("ffi_defs").libc
local SIG_BLOCK, O_NONBLOCK
do
  local _obj_0 = require("lib.os_constants")
  SIG_BLOCK, O_NONBLOCK = _obj_0.SIG_BLOCK, _obj_0.O_NONBLOCK
end
for _, c in ipairs({
  "typedef struct { uint8_t _opaque[128]; } sigset_t_custos;",
  [[int sigprocmask(int how, const sigset_t_custos *set,
                    sigset_t_custos *oldset);
    int signalfd(int fd, const sigset_t_custos *mask, int flags);
    long read(int fd, void *buf, unsigned long n);
    int close(int fd);]],
  "typedef struct { uint32_t ssi_signo; uint8_t _pad[124]; } signalfd_siginfo;"
}) do
  pcall(ffi.cdef, c)
end
local SIGHUP = 1
local make_mask
make_mask = function(signo)
  local mask = ffi.new("sigset_t_custos")
  ffi.fill(mask, ffi.sizeof(mask), 0)
  local word = ffi.cast("uint32_t*", mask)
  word[0] = bit.lshift(1, signo - 1)
  return mask
end
local watcher_mt = {
  __index = {
    pending = function(self)
      local seen = false
      while true do
        local n = tonumber(libc.read(self.fd, self._siginfo, self._size))
        if n ~= self._size then
          break
        end
        if tonumber(self._siginfo.ssi_signo) == self.signo then
          seen = true
        end
      end
      return seen
    end,
    close = function(self)
      libc.close(self.fd)
      return nil
    end
  }
}
local create_watcher
create_watcher = function(signo)
  if signo == nil then
    signo = SIGHUP
  end
  local mask = make_mask(signo)
  if libc.sigprocmask(SIG_BLOCK, mask, nil) ~= 0 then
    error("sigprocmask() échoué pour le signal " .. tostring(signo))
  end
  local fd = libc.signalfd(-1, mask, O_NONBLOCK)
  if fd < 0 then
    error("signalfd() échoué pour le signal " .. tostring(signo))
  end
  return setmetatable({
    fd = fd,
    signo = signo,
    _siginfo = ffi.new("signalfd_siginfo"),
    _size = ffi.sizeof("signalfd_siginfo")
  }, watcher_mt)
end
return {
  SIGHUP = SIGHUP,
  create_watcher = create_watcher,
  make_mask = make_mask
}
