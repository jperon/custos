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
local probe_ipv6
probe_ipv6 = require("doh.upstream").probe_ipv6
local SIGTERM, SIGHUP, WNOHANG, set_process_name, fork_worker, shutdown_workers
do
  local _obj_0 = require("lib.process")
  SIGTERM, SIGHUP, WNOHANG, set_process_name, fork_worker, shutdown_workers = _obj_0.SIGTERM, _obj_0.SIGHUP, _obj_0.WNOHANG, _obj_0.set_process_name, _obj_0.fork_worker, _obj_0.shutdown_workers
end
set_process_name("custos")
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
    local errno = tonumber(ffi.C.__errno_location()[0])
    log_warn({
      action = "pipe_resize_failed",
      name = name,
      fd = fds[1],
      rc = sz,
      errno = errno
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
    learn = create_pipe("mac_learn"),
    events = create_pipe("events"),
    nft = create_pipe("nft")
  }
end
local load_auth_cfg
load_auth_cfg = function()
  local load_config
  load_config = require("filter.lib.load_config").load_config
  local filter_cfg_path = os.getenv("CUSTOS_FILTER_CONFIG") or "/etc/custos/filter.yml"
  local filter_cfg, cfg_err = load_config(filter_cfg_path)
  if not (filter_cfg) then
    log_warn({
      action = "auth_cfg_load_warning",
      path = filter_cfg_path,
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
local load_doh_cfg
load_doh_cfg = function()
  return {
    enabled = config.DOH_ENABLED == "1",
    port = tonumber(config.DOH_PORT) or 8443,
    upstream_ip = (function()
      if config.DOH_PREFER_IPV6 == "1" and probe_ipv6(config.DOH_UPSTREAM_IPV6) then
        return config.DOH_UPSTREAM_IPV6
      else
        return config.DOH_UPSTREAM_IPV4
      end
    end)(),
    upstream_port = tonumber(config.DOH_UPSTREAM_PORT) or 53,
    timeout_ms = tonumber(config.DOH_UPSTREAM_TIMEOUT_MS) or 2000,
    cert_path = (function()
      if config.DOH_CERT_PATH and #config.DOH_CERT_PATH > 0 then
        return config.DOH_CERT_PATH
      else
        return nil
      end
    end)(),
    key_path = (function()
      if config.DOH_KEY_PATH and #config.DOH_KEY_PATH > 0 then
        return config.DOH_KEY_PATH
      else
        return nil
      end
    end)()
  }
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
    if pipes.events then
      if pipes.events.rfd then
        libc.close(pipes.events.rfd)
      end
      if pipes.events.wfd then
        libc.close(pipes.events.wfd)
      end
    end
    if pipes.nft then
      if pipes.nft.rfd then
        libc.close(pipes.nft.rfd)
      end
      if pipes.nft.wfd then
        libc.close(pipes.nft.wfd)
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
  local bridge_ifname = auth_cfg.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"
  local detect_bridge_slaves
  detect_bridge_slaves = function()
    local handle = io.popen("ip -brief link show type bridge_slave 2>/dev/null")
    if not (handle) then
      return nil
    end
    local slaves = { }
    for line in handle:lines() do
      local ifname = line:match("^(%S+)")
      if ifname then
        table.insert(slaves, ifname)
      end
    end
    handle:close()
    return #slaves > 0 and slaves or nil
  end
  local bridge_slaves = detect_bridge_slaves() or {
    bridge_ifname
  }
  log_info({
    action = "bridge_slaves_detected",
    count = #bridge_slaves,
    interfaces = table.concat(bridge_slaves, ",")
  })
  local workers = {
    {
      name = "mac-lrn",
      pid = nil,
      restart_fn = function()
        return fork_worker("mac-lrn", function(rfd)
          return require("mac_learner").run(rfd, bridge_ifname)
        end, pipes.learn.rfd)
      end
    }
  }
  local ack_pipes = { }
  local ack_wfds = { }
  local next_widx = 0
  local alloc_ack_pipe
  alloc_ack_pipe = function()
    local p = create_pipe("ack_" .. tostring(next_widx))
    ack_pipes[#ack_pipes + 1] = p
    ack_wfds[next_widx + 1] = p.wfd
    local widx = next_widx
    next_widx = next_widx + 1
    return {
      rfd = p.rfd,
      worker_idx = widx
    }
  end
  table.insert(workers, {
    name = "nft",
    pid = nil,
    restart_fn = function()
      return fork_worker("nft", function(args)
        return require("worker_nft").run(args.rfd, args.ack_wfds)
      end, {
        rfd = pipes.nft.rfd,
        ack_wfds = ack_wfds
      })
    end
  })
  table.insert(workers, {
    name = "events",
    pid = nil,
    restart_fn = function()
      return fork_worker("events", (function(fds)
        return require("worker_events").run(fds.rfd, fds.dir, fds.max_age_hours, fds.min_free_pct)
      end), {
        rfd = pipes.events.rfd,
        dir = config.EVENTS_DIR or "/tmp/custos/events",
        max_age_hours = config.EVENTS_MAX_AGE_HOURS or 168,
        min_free_pct = config.EVENTS_MIN_FREE_PCT or 30
      })
    end
  })
  table.insert(workers, {
    name = "arp",
    pid = nil,
    restart_fn = function()
      return fork_worker("arp", function(wfd)
        return require("worker_arp_sniffer").run(bridge_ifname, wfd)
      end, pipes.learn.wfd)
    end
  })
  local auth_queue_num = tonumber(config.QUEUE_AUTH) or 5
  table.insert(workers, {
    name = "auth-q",
    pid = nil,
    restart_fn = function()
      return fork_worker("auth-q", function(wfd)
        return require("worker_auth_queue").run(auth_queue_num, wfd)
      end, pipes.learn.wfd)
    end
  })
  for i, q_num in ipairs(questions_queues) do
    table.insert(workers, {
      name = "dns-q" .. tostring(q_num),
      pid = nil,
      restart_fn = function()
        return fork_worker("dns-q" .. tostring(q_num), (function(fds)
          return require("worker_questions").run(q_num, fds.q0q1_wfd, fds.learn_wfd, fds.events_wfd)
        end), {
          q0q1_wfd = pipes.q0q1.wfd,
          learn_wfd = pipes.learn.wfd,
          events_wfd = pipes.events.wfd
        })
      end
    })
  end
  for i, q_num in ipairs(responses_queues) do
    local ack_info = alloc_ack_pipe()
    table.insert(workers, {
      name = "resp-q" .. tostring(q_num),
      pid = nil,
      restart_fn = function()
        return fork_worker("resp-q" .. tostring(q_num), function(fds)
          return require("worker_responses").run(q_num, fds)
        end, {
          q0q1_rfd = pipes.q0q1.rfd,
          nft_wfd = pipes.nft.wfd,
          ack_rfd = ack_info.rfd,
          worker_idx = ack_info.worker_idx
        })
      end
    })
  end
  for i, q_num in ipairs(captive_queues) do
    table.insert(workers, {
      name = "cap-q" .. tostring(q_num),
      pid = nil,
      restart_fn = function()
        return fork_worker("cap-q" .. tostring(q_num), function(cfg)
          return require("worker_captive").run(q_num, cfg)
        end, auth_cfg)
      end
    })
  end
  for i, q_num in ipairs(reject_queues) do
    table.insert(workers, {
      name = "rej-q" .. tostring(q_num),
      pid = nil,
      restart_fn = function()
        return fork_worker("rej-q" .. tostring(q_num), function(cfg)
          return require("worker_reject").run(q_num, cfg)
        end, auth_cfg)
      end
    })
  end
  local sni_queue_num = tonumber(config.QUEUE_SNI_LOG) or 6
  if config.QUEUE_SNI_LOG then
    table.insert(workers, {
      name = "tls-log",
      pid = nil,
      restart_fn = function()
        return fork_worker("tls-log", function(fds)
          return require("worker_tls").run(tonumber(fds.q_num), fds.events_wfd)
        end, {
          q_num = sni_queue_num,
          events_wfd = pipes.events.wfd
        })
      end
    })
  end
  table.insert(workers, {
    name = "auth",
    pid = nil,
    restart_fn = function()
      return fork_worker("auth", function(cfg)
        return require("auth.worker").run_auth_worker(cfg)
      end, auth_cfg)
    end
  })
  local doh_cfg = load_doh_cfg()
  if doh_cfg.enabled then
    doh_cfg.nft_wfd = pipes.nft.wfd
    local doh_ack_info = alloc_ack_pipe()
    doh_cfg.ack_rfd = doh_ack_info.rfd
    doh_cfg.worker_idx = doh_ack_info.worker_idx
    table.insert(workers, {
      name = "doh",
      pid = nil,
      restart_fn = function()
        return fork_worker("doh", function(cfg)
          return require("worker_doh").run(cfg)
        end, doh_cfg)
      end
    })
  end
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
          if (w.name:match("^questions%-q") or w.name:match("^responses%-q") or w.name:match("^captive%-q") or w.name:match("^reject%-q") or w.name == "DOH") and w.pid and w.pid > 0 then
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
        for _index_0 = 1, #ack_pipes do
          local p = ack_pipes[_index_0]
          libc.close(p.rfd)
          libc.close(p.wfd)
        end
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
  learn_wfd = pipes.learn.wfd,
  events_rfd = pipes.events.rfd,
  events_wfd = pipes.events.wfd
})
return supervise(pipes, sfd)
