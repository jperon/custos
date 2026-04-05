local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local log_info, log_warn, log_error
do
  local _obj_0 = require("log")
  log_info, log_warn, log_error = _obj_0.log_info, _obj_0.log_warn, _obj_0.log_error
end
ffi.cdef([[  unsigned int sleep(unsigned int seconds);
  int getpid(void);
]])
local WNOHANG = 1
local create_pipe
create_pipe = function()
  local fds = ffi.new("int[2]")
  local rc = libc.pipe2(fds, 2048)
  if rc ~= 0 then
    error("pipe2() échoué")
  end
  return {
    rfd = fds[0],
    wfd = fds[1]
  }
end
local fork_worker
fork_worker = function(name, worker_fn, pipe_fd)
  local pid = libc.fork()
  if pid < 0 then
    error("fork() échoué pour " .. tostring(name))
  end
  if pid == 0 then
    worker_fn(pipe_fd)
    libc._exit(0)
  end
  log_info({
    action = "worker_started",
    name = name,
    pid = tonumber(pid)
  })
  return pid
end
local supervise
supervise = function(pipe)
  local workers = {
    {
      name = "Q0-questions",
      pid = nil,
      restart_fn = function()
        return fork_worker("Q0-questions", (function()
          return require("worker_q0").run(pipe.wfd)
        end), pipe.wfd)
      end
    },
    {
      name = "Q1-responses",
      pid = nil,
      restart_fn = function()
        return fork_worker("Q1-responses", (function()
          return require("worker_q1").run(pipe.rfd)
        end), pipe.rfd)
      end
    }
  }
  for _index_0 = 1, #workers do
    local w = workers[_index_0]
    w.pid = w.restart_fn()
  end
  local status = ffi.new("int[1]")
  log_info({
    action = "supervisor_running",
    pid = tonumber(libc.getpid())
  })
  while true do
    local dead_pid = tonumber(libc.waitpid(-1, status, WNOHANG))
    if dead_pid > 0 then
      for _index_0 = 1, #workers do
        local w = workers[_index_0]
        if w.pid == dead_pid then
          local exit_code = bit.rshift(bit.band(status[0], 0xFF00), 8)
          log_warn({
            action = "worker_died",
            name = w.name,
            pid = dead_pid,
            exit_code = exit_code
          })
          ffi.C.sleep(1)
          w.pid = w.restart_fn()
          break
        end
      end
    else
      ffi.C.sleep(1)
    end
  end
end
log_info({
  action = "dns-filter_start",
  version = "1.0.0"
})
local pipe = create_pipe()
log_info({
  action = "ipc_pipe_created",
  rfd = pipe.rfd,
  wfd = pipe.wfd
})
return supervise(pipe)
