local ffi
ffi = require("ffi_defs").ffi
local LOCK_EX = 2
local LOCK_UN = 8
local O_RDWR = 0x0002
local O_CREAT = 0x0040
pcall(ffi.cdef, [[ int flock(int fd, int operation); ]])
local with_lock
with_lock = function(lock_path, fn)
  if not (lock_path) then
    error("with_lock: lock_path requis")
  end
  local fd = ffi.C.open(lock_path, O_RDWR + O_CREAT, ffi.cast("unsigned int", 0x180))
  if fd < 0 then
    error("with_lock: impossible d'ouvrir le verrou " .. tostring(lock_path))
  end
  if ffi.C.flock(fd, LOCK_EX) ~= 0 then
    ffi.C.close(fd)
    return fn()
  end
  local results = {
    pcall(fn)
  }
  ffi.C.flock(fd, LOCK_UN)
  ffi.C.close(fd)
  if not (results[1]) then
    error(results[2])
  end
  return unpack(results, 2)
end
return {
  with_lock = with_lock
}
