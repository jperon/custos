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
local bit = require("bit")
local SIG_UNBLOCK = 1
local SIGTERM = 15
local SIGHUP = 1
local WNOHANG = 1
local unblock_worker_signals
unblock_worker_signals = function()
  local unmask = ffi.new("sigset_t_custos")
  ffi.fill(unmask, ffi.sizeof(unmask), 0)
  local word = ffi.cast("uint32_t*", unmask)
  word[0] = bit.bor(bit.lshift(1, SIGTERM - 1), bit.lshift(1, SIGHUP - 1))
  libc.sigprocmask(SIG_UNBLOCK, unmask, nil)
  return nil
end
local set_process_name
set_process_name = function(name)
  libc.prctl(15, ffi.cast("unsigned long", ffi.cast("const char*", name)), 0, 0, 0)
  return nil
end
local set_parent_death_signal
set_parent_death_signal = function(name)
  if libc.prctl(1, SIGTERM, 0, 0, 0) ~= 0 then
    log_error({
      action = "prctl_failed",
      name = name
    })
    return false
  end
  return true
end
local fork_child
fork_child = function(name, child_fn, arg, opts)
  if arg == nil then
    arg = nil
  end
  if opts == nil then
    opts = nil
  end
  opts = opts or { }
  local unblock_signals = opts.unblock_signals
  if unblock_signals == nil then
    unblock_signals = true
  end
  local parent_death_signal = opts.parent_death_signal
  if parent_death_signal == nil then
    parent_death_signal = true
  end
  local log_start = opts.log_start
  if log_start == nil then
    log_start = true
  end
  local parent_pid = tonumber(libc.getpid())
  local pid = libc.fork()
  if pid < 0 then
    error("fork() échoué pour " .. tostring(name))
  end
  if pid == 0 then
    set_process_name("custos:" .. tostring(name))
    if unblock_signals then
      unblock_worker_signals()
    end
    if parent_death_signal then
      if not (set_parent_death_signal(name)) then
        libc._exit(1)
      end
      if tonumber(libc.getppid()) ~= parent_pid then
        libc._exit(0)
      end
    end
    local ok, err = pcall(child_fn, arg)
    if not (ok) then
      log_error({
        action = "child_crashed",
        name = name,
        err = tostring(err)
      })
      libc._exit(1)
    end
    libc._exit(0)
  end
  if log_start then
    log_info({
      action = "worker_started",
      name = name,
      pid = tonumber(pid)
    })
  end
  return pid
end
local fork_worker
fork_worker = function(name, worker_fn, worker_arg)
  if worker_arg == nil then
    worker_arg = nil
  end
  return fork_child(name, worker_fn, worker_arg)
end
local kill_child
kill_child = function(pid, sig)
  if sig == nil then
    sig = SIGTERM
  end
  if not (pid and pid > 0) then
    return false
  end
  return libc.kill(pid, sig) == 0
end
local terminate_workers
terminate_workers = function(workers)
  for _index_0 = 1, #workers do
    local w = workers[_index_0]
    if w.pid and w.pid > 0 then
      log_info({
        action = "worker_stopping",
        name = w.name,
        pid = w.pid
      })
      libc.kill(w.pid, SIGTERM)
    end
  end
  return nil
end
local wait_all_children
wait_all_children = function()
  local status = ffi.new("int[1]")
  local dead = libc.waitpid(-1, status, 0)
  while dead > 0 do
    dead = libc.waitpid(-1, status, 0)
  end
  return nil
end
local shutdown_workers
shutdown_workers = function(workers)
  terminate_workers(workers)
  return wait_all_children()
end
local reap_one
reap_one = function()
  local status = ffi.new("int[1]")
  local dead_pid = tonumber(libc.waitpid(-1, status, WNOHANG))
  local exit_code = 0
  if dead_pid and dead_pid > 0 then
    exit_code = bit.rshift(bit.band(status[0], 0xFF00), 8)
  end
  return dead_pid, exit_code
end
return {
  SIGTERM = SIGTERM,
  SIGHUP = SIGHUP,
  WNOHANG = WNOHANG,
  set_process_name = set_process_name,
  unblock_worker_signals = unblock_worker_signals,
  set_parent_death_signal = set_parent_death_signal,
  fork_child = fork_child,
  fork_worker = fork_worker,
  kill_child = kill_child,
  terminate_workers = terminate_workers,
  wait_all_children = wait_all_children,
  shutdown_workers = shutdown_workers,
  reap_one = reap_one
}
