local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local log_info, log_warn, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.set_action_prefix
end
local bit = require("bit")
local POLLIN = 1
local POLL_TIMEOUT = 60000
local O_NONBLOCK = 2048
local SIG_BLOCK = 0
local SIGTERM = 15
local READ_BUF = 65536
local O_WRONLY = 1
local O_CREAT = 64
local O_EXCL = 128
local O_APPEND = 1024
local FILE_MODE = 420
local HEADER = "decision\tqname\tmac_src\tsrc_ip\tdst_ip\tvlan\tuser\taf\treason\trule\tcount\tfirst_ts\tlast_ts\n"
local _read_buf = ffi.new("uint8_t[?]", READ_BUF)
local current_hour
current_hour = function()
  return os.date("%Y-%m-%d-%H")
end
local create_signal_fd
create_signal_fd = function()
  local mask = ffi.new("sigset_t_custos")
  ffi.fill(mask, ffi.sizeof(mask), 0)
  local word = ffi.cast("uint32_t*", mask)
  word[0] = bit.bor(word[0], bit.lshift(1, SIGTERM - 1))
  libc.sigprocmask(SIG_BLOCK, mask, nil)
  local fd = libc.signalfd(-1, mask, O_NONBLOCK)
  if fd < 0 then
    error("signalfd() échoué")
  end
  return fd
end
local read_chunk
read_chunk = function(fd)
  local n = libc.read(fd, _read_buf, READ_BUF)
  if n > 0 then
    return ffi.string(_read_buf, n)
  elseif n == 0 then
    return nil
  else
    return ""
  end
end
local process_line
process_line = function(line, agg)
  local tab_pos = line:find("\t")
  if not (tab_pos) then
    return 
  end
  local ts_str = line:sub(1, tab_pos - 1)
  local key = line:sub(tab_pos + 1)
  if key == "" then
    return 
  end
  local entry = agg[key]
  if entry then
    entry.count = entry.count + 1
    entry.last_ts = ts_str
  else
    agg[key] = {
      count = 1,
      first_ts = ts_str,
      last_ts = ts_str
    }
  end
end
local flush_to_file
flush_to_file = function(agg, hour, events_dir)
  local has_entries = false
  for _ in pairs(agg) do
    has_entries = true
    break
  end
  if not (has_entries) then
    return 
  end
  local path = tostring(events_dir) .. "/events-" .. tostring(hour) .. ".tsv"
  local fd_excl = libc.open(path, bit.bor(O_WRONLY, O_CREAT, O_EXCL), FILE_MODE)
  if fd_excl >= 0 then
    libc.write(fd_excl, HEADER, #HEADER)
    libc.close(fd_excl)
  end
  local fd = libc.open(path, bit.bor(O_WRONLY, O_CREAT, O_APPEND), FILE_MODE)
  if fd < 0 then
    local errno = tonumber(ffi.C.__errno_location()[0])
    log_warn(function()
      return {
        action = "open_failed",
        path = path,
        errno = errno
      }
    end)
    return 
  end
  for key, entry in pairs(agg) do
    local line = tostring(key) .. "\t" .. tostring(entry.count) .. "\t" .. tostring(entry.first_ts) .. "\t" .. tostring(entry.last_ts) .. "\n"
    libc.write(fd, line, #line)
  end
  return libc.close(fd)
end
local compress_old
compress_old = function(events_dir, current_hour_str)
  local current_file = "events-" .. tostring(current_hour_str) .. ".tsv"
  local fh = io.popen("find '" .. tostring(events_dir) .. "' -maxdepth 1 -name 'events-*.tsv' -type f")
  if not (fh) then
    return 
  end
  for path in fh:lines() do
    local fname = path:match("([^/]+)$")
    if fname and fname ~= current_file then
      os.execute("zstd -q --rm '" .. tostring(path) .. "'")
    end
  end
  return fh:close()
end
local free_pct_on
free_pct_on = function(path)
  local fh = io.popen("df -k '" .. tostring(path) .. "' 2>/dev/null | tail -1")
  if not (fh) then
    return nil
  end
  local line = fh:read("*l")
  fh:close()
  if not (line) then
    return nil
  end
  local use_str = line:match("(%d+)%%")
  if not (use_str) then
    return nil
  end
  local use = tonumber(use_str)
  if not (use) then
    return nil
  end
  return 100 - use
end
local file_age_hours
file_age_hours = function(fname)
  local y, mo, d, h = fname:match("^events%-(%d%d%d%d)%-(%d%d)%-(%d%d)%-(%d%d)%.tsv%.zst$")
  if not (y) then
    return nil
  end
  local file_epoch = os.time({
    year = tonumber(y),
    month = tonumber(mo),
    day = tonumber(d),
    hour = tonumber(h),
    min = 0,
    sec = 0
  })
  return (os.time() - file_epoch) / 3600
end
local cleanup_old
cleanup_old = function(events_dir, max_age_hours, min_free_pct)
  local fh = io.popen("find '" .. tostring(events_dir) .. "' -maxdepth 1 -name 'events-*.tsv.zst' -type f 2>/dev/null")
  if not (fh) then
    return 
  end
  local files
  do
    local _accum_0 = { }
    local _len_0 = 1
    for path in fh:lines() do
      _accum_0[_len_0] = path
      _len_0 = _len_0 + 1
    end
    files = _accum_0
  end
  fh:close()
  if #files == 0 then
    return 
  end
  table.sort(files)
  for _index_0 = 1, #files do
    local path = files[_index_0]
    local fname = path:match("([^/]+)$")
    local age = file_age_hours(fname)
    if age and age > max_age_hours then
      os.remove(path)
      log_info(function()
        return {
          action = "events_cleanup_age",
          file = fname,
          age_h = math.floor(age)
        }
      end)
    end
  end
  local free = free_pct_on(events_dir)
  if not (free and free < min_free_pct) then
    return 
  end
  local fh2 = io.popen("find '" .. tostring(events_dir) .. "' -maxdepth 1 -name 'events-*.tsv.zst' -type f 2>/dev/null")
  if not (fh2) then
    return 
  end
  local remaining
  do
    local _accum_0 = { }
    local _len_0 = 1
    for path in fh2:lines() do
      _accum_0[_len_0] = path
      _len_0 = _len_0 + 1
    end
    remaining = _accum_0
  end
  fh2:close()
  table.sort(remaining)
  for _index_0 = 1, #remaining do
    local path = remaining[_index_0]
    free = free_pct_on(events_dir)
    if not (free and free < min_free_pct) then
      break
    end
    local fname = path:match("([^/]+)$")
    os.remove(path)
    log_info(function()
      return {
        action = "events_cleanup_space",
        file = fname,
        free_pct = free
      }
    end)
  end
end
local run
run = function(events_rfd, events_dir, max_age_hours, min_free_pct)
  set_action_prefix("events_")
  os.execute("mkdir -p '" .. tostring(events_dir) .. "'")
  local sfd = create_signal_fd()
  local pfds = ffi.new("struct pollfd[2]")
  pfds[0].fd = events_rfd
  pfds[0].events = POLLIN
  pfds[1].fd = sfd
  pfds[1].events = POLLIN
  local agg = { }
  local line_buf = ""
  local hour = current_hour()
  local siginfo = ffi.new("signalfd_siginfo")
  local sig_sz = ffi.sizeof("signalfd_siginfo")
  log_info(function()
    return {
      action = "start",
      events_dir = events_dir,
      hour = hour,
      max_age_hours = max_age_hours,
      min_free_pct = min_free_pct
    }
  end)
  cleanup_old(events_dir, max_age_hours, min_free_pct)
  while true do
    libc.poll(pfds, 2, POLL_TIMEOUT)
    if bit.band(pfds[1].revents, POLLIN) ~= 0 then
      libc.read(sfd, siginfo, sig_sz)
      if siginfo.ssi_signo == SIGTERM then
        log_info(function()
          return {
            action = "sigterm",
            hour = hour
          }
        end)
        flush_to_file(agg, hour, events_dir)
        libc._exit(0)
      end
    end
    if bit.band(pfds[0].revents, POLLIN) ~= 0 then
      local chunk = read_chunk(events_rfd)
      if chunk == nil then
        log_warn(function()
          return {
            action = "pipe_eof",
            fd = events_rfd
          }
        end)
      elseif #chunk > 0 then
        line_buf = line_buf .. chunk
        while true do
          local nl = line_buf:find("\n", 1, true)
          if not (nl) then
            break
          end
          local line = line_buf:sub(1, nl - 1)
          line_buf = line_buf:sub(nl + 1)
          if #line > 0 then
            process_line(line, agg)
          end
        end
      end
    end
    local new_hour = current_hour()
    if new_hour ~= hour then
      log_info(function()
        return {
          action = "hour_change",
          old = hour,
          new = new_hour
        }
      end)
      flush_to_file(agg, hour, events_dir)
      compress_old(events_dir, new_hour)
      cleanup_old(events_dir, max_age_hours, min_free_pct)
      agg = { }
      hour = new_hour
    end
  end
end
return {
  run = run
}
