local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local run_cmd
run_cmd = require("nft").run_cmd
local cmd_for
cmd_for = require("nft_queue").cmd_for
local log_info, log_warn, log_debug, set_action_prefix
do
  local _obj_0 = require("log")
  log_info, log_warn, log_debug, set_action_prefix = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_debug, _obj_0.set_action_prefix
end
local BUF_SIZE = 8192
local MAX_BATCH = 64
local FLUSH_MS = 50
local EAGAIN = 11
local EWOULDBLOCK = 11
local sleep_req = ffi.new("timespec_t[1]")
local read_buf = ffi.new("char[?]", BUF_SIZE)
local sleep_ms
sleep_ms = function(ms)
  sleep_req[0].tv_sec = math.floor(ms / 1000)
  sleep_req[0].tv_nsec = (ms % 1000) * 1000000
  return libc.nanosleep(sleep_req, nil)
end
local parse_line
parse_line = function(line)
  local kind, key, ip = line:match("^([^|]+)|([^|]+)|([^|]+)$")
  return kind, key, ip
end
local flush_batch
flush_batch = function(pending)
  local count = 0
  for _, _ in pairs(pending) do
    count = count + 1
  end
  if count == 0 then
    return 
  end
  local lines = { }
  for _, item in pairs(pending) do
    local cmd = cmd_for(item.kind, item.key, item.ip)
    if cmd then
      lines[#lines + 1] = cmd
    end
  end
  for k in pairs(pending) do
    pending[k] = nil
  end
  if #lines == 0 then
    return 
  end
  local cmd = table.concat(lines, "\n")
  local ok, err = run_cmd(cmd, {
    quiet = true
  })
  if ok then
    return log_debug({
      action = "batch_ok",
      count = #lines
    })
  else
    log_warn({
      action = "batch_failed",
      count = #lines,
      err = err or ""
    })
    for _index_0 = 1, #lines do
      local line = lines[_index_0]
      local ok_one, err_one = run_cmd(line, {
        quiet = true
      })
      if not (ok_one) then
        log_warn({
          action = "single_failed",
          err = err_one or "",
          cmd = line
        })
      end
    end
  end
end
local run
run = function(rfd)
  set_action_prefix("nft_")
  log_info({
    action = "worker_start",
    rfd = rfd
  })
  local pending = { }
  local partial = ""
  local last_flush = os.clock()
  while true do
    local n = libc.read(rfd, read_buf, BUF_SIZE)
    if n and n > 0 then
      local data = partial .. ffi.string(read_buf, n)
      partial = ""
      while true do
        local nl = data:find("\n", 1, true)
        if not (nl) then
          break
        end
        local line = data:sub(1, nl - 1)
        data = data:sub(nl + 1)
        local kind, key, ip = parse_line(line)
        if kind and key and ip then
          pending[tostring(kind) .. "|" .. tostring(key) .. "|" .. tostring(ip)] = {
            kind = kind,
            key = key,
            ip = ip
          }
        end
      end
      partial = data
    else
      local errno_p = libc.__errno_location()
      local errno
      if errno_p then
        errno = errno_p[0]
      else
        errno = 0
      end
      if n == 0 then
        log_warn({
          action = "pipe_closed"
        })
        return 
      end
      if errno ~= EAGAIN and errno ~= EWOULDBLOCK then
        log_warn({
          action = "read_failed",
          errno = errno
        })
        sleep_ms(100)
      end
    end
    local now_clock = os.clock()
    local pending_count = 0
    for _, _ in pairs(pending) do
      pending_count = pending_count + 1
    end
    if pending_count >= MAX_BATCH or (pending_count > 0 and (now_clock - last_flush) * 1000 >= FLUSH_MS) then
      flush_batch(pending)
      last_flush = os.clock()
    else
      sleep_ms(10)
    end
  end
end
return {
  run = run
}
