local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local log_warn
log_warn = require("log").log_warn
local PIPE_BUF_ATOMIC = 4096
local write_buf
write_buf = function(fd, buf, len)
  local n = libc.write(fd, buf, len)
  if n == len then
    return true
  end
  local errno_p = libc.__errno_location()
  local errno
  if errno_p then
    errno = tonumber(errno_p[0])
  else
    errno = 0
  end
  log_warn(function()
    return {
      action = "pipe_batch_write_failed",
      fd = fd,
      bytes = len,
      written = tonumber(n) or -1,
      errno = errno
    }
  end)
  return false
end
local new_records
new_records = function(fd, rec_size, capacity)
  if capacity == nil then
    capacity = PIPE_BUF_ATOMIC
  end
  if not (rec_size and rec_size > 0) then
    return nil
  end
  local cap = math.floor(capacity / rec_size) * rec_size
  if cap < rec_size then
    return nil
  end
  local buf = ffi.new("uint8_t[?]", cap)
  local nbytes = 0
  local ncount = 0
  local flush
  flush = function()
    if ncount == 0 then
      return true
    end
    local ok = write_buf(fd, buf, nbytes)
    nbytes = 0
    ncount = 0
    return ok
  end
  local add
  add = function(msg)
    if not (fd) then
      return false
    end
    if not (type(msg) == "string") then
      log_warn(function()
        return {
          action = "pipe_batch_record_size_invalid",
          bytes = -1,
          max = rec_size
        }
      end)
      return false
    end
    if not (#msg == rec_size) then
      log_warn(function()
        return {
          action = "pipe_batch_record_size_invalid",
          bytes = #msg,
          max = rec_size
        }
      end)
      return false
    end
    if nbytes + rec_size > cap then
      if not (flush()) then
        return false
      end
    end
    ffi.copy(buf + nbytes, msg, rec_size)
    nbytes = nbytes + rec_size
    ncount = ncount + 1
    return true
  end
  return {
    fd = fd,
    add = add,
    flush = flush,
    pending = function()
      return ncount
    end,
    bytes = function()
      return nbytes
    end
  }
end
local new_lines
new_lines = function(fd, capacity)
  if capacity == nil then
    capacity = PIPE_BUF_ATOMIC
  end
  local parts = { }
  local nbytes = 0
  local flush
  flush = function()
    if #parts == 0 then
      return true
    end
    local data = table.concat(parts)
    local ok = write_buf(fd, data, #data)
    parts = { }
    nbytes = 0
    return ok
  end
  local add
  add = function(line)
    if not (fd) then
      return false
    end
    if not (type(line) == "string" and #line > 0) then
      return false
    end
    if #line > capacity then
      log_warn(function()
        return {
          action = "pipe_batch_line_too_long",
          bytes = #line,
          max = capacity
        }
      end)
      return false
    end
    if nbytes + #line > capacity then
      if not (flush()) then
        return false
      end
    end
    parts[#parts + 1] = line
    nbytes = nbytes + #line
    return true
  end
  return {
    fd = fd,
    add = add,
    flush = flush,
    pending = function()
      return #parts
    end,
    bytes = function()
      return nbytes
    end
  }
end
return {
  new_records = new_records,
  new_lines = new_lines,
  write_buf = write_buf,
  PIPE_BUF_ATOMIC = PIPE_BUF_ATOMIC
}
