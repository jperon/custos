local ffi, libc
do
  local _obj_0 = require("ffi_defs")
  ffi, libc = _obj_0.ffi, _obj_0.libc
end
local log_info, log_warn
do
  local _obj_0 = require("log")
  log_info, log_warn = _obj_0.log_info, _obj_0.log_warn
end
local SIGTERM, SIGHUP, WNOHANG, fork_worker, shutdown_workers
do
  local _obj_0 = require("lib.process")
  SIGTERM, SIGHUP, WNOHANG, fork_worker, shutdown_workers = _obj_0.SIGTERM, _obj_0.SIGHUP, _obj_0.WNOHANG, _obj_0.fork_worker, _obj_0.shutdown_workers
end
local bit = require("bit")
local config = require("config")
local filter = require("filter")
local nft_rules = require("nft_rules")
local nft_extra = require("nft_extra_rules")
ffi.cdef([[  unsigned int sleep(unsigned int seconds);
]])
local SIG_BLOCK = 0
local O_NONBLOCK = 2048
local F_SETPIPE_SZ = 1031
local PIPE_DESIRED_SIZE = 65536
local create_signal_fd
create_signal_fd = function()
  local mask = ffi.new("sigset_t_custos")
  ffi.fill(mask, ffi.sizeof(mask), 0)
  local word = ffi.cast("uint32_t*", mask)
  word[0] = bit.bor(word[0], bit.lshift(1, SIGTERM - 1))
  word[0] = bit.bor(word[0], bit.lshift(1, SIGHUP - 1))
  libc.sigprocmask(SIG_BLOCK, mask, nil)
  local fd = libc.signalfd(-1, mask, O_NONBLOCK)
  if fd < 0 then
    error("signalfd() échoué")
  end
  return fd
end
local create_pipe
create_pipe = function(name)
  local fds = ffi.new("int[2]")
  local rc = libc.pipe2(fds, O_NONBLOCK)
  if rc ~= 0 then
    error("pipe2() échoué pour " .. tostring(name))
  end
  local sz = libc.fcntl(fds[1], F_SETPIPE_SZ, PIPE_DESIRED_SIZE)
  if sz and sz >= 0 then
    log_info({
      action = "pipe_resize",
      name = name,
      fd = fds[1],
      new_size = sz
    })
  else
    log_warn({
      action = "pipe_resize_failed",
      name = name,
      fd = fds[1],
      rc = sz
    })
  end
  return {
    rfd = fds[0],
    wfd = fds[1]
  }
end
local create_pipes
create_pipes = function()
  return {
    q0q1 = create_pipe("q0q1"),
    learn = create_pipe("mac_learn")
  }
end
local load_auth_cfg
load_auth_cfg = function()
  local load_config
  load_config = require("filter.lib.load_config").load_config
  local filter_cfg, cfg_err = load_config(os.getenv("CUSTOS_FILTER_CONFIG") or "/etc/custos/filter.yml")
  if not (filter_cfg) then
    log_warn({
      action = "auth_cfg_load_warning",
      err = cfg_err
    })
    filter_cfg = {
      auth = { }
    }
  end
  local auth = filter_cfg.auth or { }
  auth.port = auth.port or 33443
  auth.idle_timeout = auth.idle_timeout or 120
  auth.heartbeat_interval = auth.heartbeat_interval or 30
  auth.session_ttl = auth.session_ttl or 0
  auth.secrets = auth.secrets or "/etc/custos/secrets"
  auth.sessions_file = auth.sessions_file or "./tmp/sessions.lua"
  return auth
end
local close_supervisor_fds
close_supervisor_fds = function(pipes)
  if pipes then
    if pipes.q0q1 then
      if pipes.q0q1.rfd then
        libc.close(pipes.q0q1.rfd)
      end
      if pipes.q0q1.wfd then
        libc.close(pipes.q0q1.wfd)
      end
    end
    if pipes.learn then
      if pipes.learn.rfd then
        libc.close(pipes.learn.rfd)
      end
      if pipes.learn.wfd then
        libc.close(pipes.learn.wfd)
      end
    end
  end
  return nil
end
local supervise
supervise = function(pipes, sfd)
  local auth_cfg = load_auth_cfg()
  local parse_queues
  parse_queues = function(str)
    local queues = { }
    for part in str:gmatch("%d+%-?%d*") do
      if part:match("%-%d+") then
        local a, b = part:match("(%d+)%-(%d+)")
        a, b = tonumber(a), tonumber(b)
        if a and b then
          if a <= b then
            for n = a, b do
              table.insert(queues, n)
            end
          else
            for n = b, a do
              table.insert(queues, n)
            end
          end
        else
          local n = tonumber(part)
          if n then
            table.insert(queues, n)
          end
        end
      else
        local n = tonumber(part)
        if n then
          table.insert(queues, n)
        end
      end
    end
    return queues
  end
  local questions_queues = parse_queues(config.QUEUE_QUESTIONS)
  local responses_queues = parse_queues(config.QUEUE_RESPONSES)
  local captive_queues = parse_queues(config.QUEUE_CAPTIVE)
  local reject_queues = parse_queues(config.QUEUE_REJECT)
  local workers = {
    {
      name = "MAC-learner",
      pid = nil,
      restart_fn = function()
        return fork_worker("MAC-learner", function(rfd)
          return require("mac_learner").run(rfd)
        end, pipes.learn.rfd)
      end
    }
  }
  local auth_queue_num = tonumber(config.QUEUE_AUTH) or 5
  table.insert(workers, {
    name = "auth_queue",
    pid = nil,
    restart_fn = function()
      return fork_worker("auth_queue", function(wfd)
        return require("worker_auth_queue").run(auth_queue_num, wfd)
      end, pipes.learn.wfd)
    end
  })
  for i, q_num in ipairs(questions_queues) do
    table.insert(workers, {
      name = "questions-q" .. tostring(q_num),
      pid = nil,
      restart_fn = function()
        return fork_worker("questions-q" .. tostring(q_num), (function(fds)
          return require("worker_questions").run(q_num, fds.q0q1_wfd, fds.learn_wfd)
        end), {
          q0q1_wfd = pipes.q0q1.wfd,
          learn_wfd = pipes.learn.wfd
        })
      end
    })
  end
  for i, q_num in ipairs(responses_queues) do
    table.insert(workers, {
      name = "responses-q" .. tostring(q_num),
      pid = nil,
      restart_fn = function()
        return fork_worker("responses-q" .. tostring(q_num), function(rfd)
          return require("worker_responses").run(q_num, rfd)
        end, pipes.q0q1.rfd)
      end
    })
  end
  for i, q_num in ipairs(captive_queues) do
    table.insert(workers, {
      name = "captive-q" .. tostring(q_num),
      pid = nil,
      restart_fn = function()
        return fork_worker("captive-q" .. tostring(q_num), function(cfg)
          return require("worker_captive").run(q_num, cfg)
        end, auth_cfg)
      end
    })
  end
  for i, q_num in ipairs(reject_queues) do
    table.insert(workers, {
      name = "reject-q" .. tostring(q_num),
      pid = nil,
      restart_fn = function()
        return fork_worker("reject-q" .. tostring(q_num), function(cfg)
          return require("worker_reject").run(q_num, cfg)
        end, auth_cfg)
      end
    })
  end
  table.insert(workers, {
    name = "AUTH",
    pid = nil,
    restart_fn = function()
      return fork_worker("AUTH", function(cfg)
        return require("auth.worker").run_auth_worker(cfg)
      end, auth_cfg)
    end
  })
  nft_rules.apply()
  filter.load()
  nft_extra.apply_from_config()
  for _index_0 = 1, #workers do
    local w = workers[_index_0]
    w.pid = w.restart_fn()
  end
  local status = ffi.new("int[1]")
  local siginfo = ffi.new("signalfd_siginfo")
  local sig_sz = ffi.sizeof("signalfd_siginfo")
  log_info({
    action = "supervisor_running",
    pid = tonumber(libc.getpid())
  })
  while true do
    local rv = libc.read(sfd, siginfo, sig_sz)
    if rv == sig_sz then
      if siginfo.ssi_signo == SIGHUP then
        log_info({
          action = "supervisor_sighup_reload"
        })
        filter.load()
        for _index_0 = 1, #workers do
          local w = workers[_index_0]
          if (w.name:match("^questions%-q") or w.name:match("^responses%-q") or w.name:match("^captive%-q") or w.name:match("^reject%-q")) and w.pid and w.pid > 0 then
            log_info({
              action = "supervisor_sighup_kill",
              name = w.name,
              pid = w.pid
            })
            libc.kill(w.pid, SIGTERM)
            status = ffi.new("int[1]")
            while libc.waitpid(w.pid, status, 0) ~= w.pid do
              local _ = nil
            end
            ffi.C.sleep(1)
            w.pid = w.restart_fn()
            log_info({
              action = "supervisor_sighup_refork",
              name = w.name,
              pid = w.pid
            })
          end
        end
        for _index_0 = 1, #workers do
          local w = workers[_index_0]
          if w.name == "AUTH" and w.pid and w.pid > 0 then
            log_info({
              action = "supervisor_sighup_forward_auth",
              pid = w.pid
            })
            libc.kill(w.pid, SIGHUP)
          end
        end
      else
        log_info({
          action = "supervisor_sigterm"
        })
        nft_extra.cleanup()
        shutdown_workers(workers)
        close_supervisor_fds(pipes)
        libc._exit(0)
      end
    end
    local dead_pid = tonumber(libc.waitpid(-1, status, WNOHANG))
    if dead_pid and dead_pid > 0 then
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
local sfd = create_signal_fd()
local pipes = create_pipes()
log_info({
  action = "ipc_pipes_created",
  q0q1_rfd = pipes.q0q1.rfd,
  q0q1_wfd = pipes.q0q1.wfd,
  learn_rfd = pipes.learn.rfd,
  learn_wfd = pipes.learn.wfd
})
return supervise(pipes, sfd)
