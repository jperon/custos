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
do
  local gc_cfg = config.runtime or { }
  if gc_cfg.gc_pause then
    collectgarbage("setpause", gc_cfg.gc_pause)
  end
  if gc_cfg.gc_stepmul then
    collectgarbage("setstepmul", gc_cfg.gc_stepmul)
  end
end
local nft_extra = require("nft_extra_rules")
local lowmem = require("lib.lowmem")
local plan_optional_workers
plan_optional_workers = require("lib.worker_plan").plan_optional_workers
ffi.cdef([[  unsigned int sleep(unsigned int seconds);
]])
local O_NONBLOCK, SIG_BLOCK
do
  local _obj_0 = require("lib.os_constants")
  O_NONBLOCK, SIG_BLOCK = _obj_0.O_NONBLOCK, _obj_0.SIG_BLOCK
end
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
    log_info(function()
      return {
        action = "pipe_resize",
        name = name,
        fd = fds[1],
        new_size = sz
      }
    end)
  else
    local errno = tonumber(ffi.C.__errno_location()[0])
    log_warn(function()
      return {
        action = "pipe_resize_failed",
        name = name,
        fd = fds[1],
        rc = sz,
        errno = errno
      }
    end)
  end
  return {
    rfd = fds[0],
    wfd = fds[1]
  }
end
local create_pipes
create_pipes = function()
  return {
    question_response = create_pipe("question_response"),
    learn = create_pipe("mac_learn"),
    events = create_pipe("events"),
    nft = create_pipe("nft")
  }
end
local load_auth_cfg
load_auth_cfg = function()
  local meta = config.__meta or { }
  local auth = { }
  for k, v in pairs(config.auth or { }) do
    auth[k] = v
  end
  auth.port = tonumber(auth.port) or 33443
  auth.idle_timeout = tonumber(auth.idle_timeout) or 120
  auth.heartbeat_interval = tonumber(auth.heartbeat_interval) or 30
  auth.session_ttl = tonumber(auth.session_ttl) or 0
  auth.secrets = auth.secrets or "/etc/custos/secrets"
  auth.sessions_file = auth.sessions_file or "/tmp/sessions.lua"
  auth.config_path = meta.path or "/etc/custos/config.moon"
  return auth
end
local load_doh_cfg
load_doh_cfg = function()
  return {
    enabled = config.doh.enabled,
    port = tonumber(config.doh.port) or 8443,
    upstream_ip = (function()
      if config.doh.prefer_ipv6 and probe_ipv6(config.doh.upstream_ipv6) then
        return config.doh.upstream_ipv6
      else
        return config.doh.upstream_ipv4
      end
    end)(),
    upstream_port = tonumber(config.doh.upstream_port) or 53,
    timeout_ms = tonumber(config.doh.upstream_timeout_ms) or 2000,
    cert = (function()
      if config.doh.cert and #config.doh.cert > 0 then
        return config.doh.cert
      else
        return nil
      end
    end)(),
    key = (function()
      if config.doh.key and #config.doh.key > 0 then
        return config.doh.key
      else
        return nil
      end
    end)()
  }
end
local close_supervisor_fds
close_supervisor_fds = function(pipes)
  if pipes then
    if pipes.question_response then
      if pipes.question_response.rfd then
        libc.close(pipes.question_response.rfd)
      end
      if pipes.question_response.wfd then
        libc.close(pipes.question_response.wfd)
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
  local parse_queues = lowmem.parse_queues
  local is_lowmem = lowmem.detect(config.runtime)
  if is_lowmem then
    local collapsed = lowmem.collapse_nfqueue(config.nfqueue)
    log_info(function()
      return {
        action = "lowmem_collapse_queues",
        collapsed = collapsed
      }
    end)
  end
  local optional = plan_optional_workers(config, is_lowmem)
  local questions_queues = parse_queues(config.nfqueue.questions)
  local responses_queues = parse_queues(config.nfqueue.responses)
  local captive_queues = parse_queues(config.nfqueue.captive)
  local reject_queues = parse_queues(config.nfqueue.reject)
  local bridge_ifname = auth_cfg.bridge_ifname or "br0"
  local read_lines
  read_lines = function(cmd)
    local handle = io.popen(cmd)
    if not (handle) then
      return { }
    end
    local out = { }
    for line in handle:lines() do
      local ifname = line:match("^(%S+)")
      if ifname then
        table.insert(out, ifname)
      end
    end
    handle:close()
    return out
  end
  local detect_bridge_slaves
  detect_bridge_slaves = function()
    local slaves = read_lines("ls -1 /sys/class/net/" .. tostring(bridge_ifname) .. "/brif/ 2>/dev/null")
    if #slaves > 0 then
      return slaves
    end
    slaves = read_lines("ip -brief link show type bridge_slave 2>/dev/null")
    return #slaves > 0 and slaves or nil
  end
  local bridge_slaves = detect_bridge_slaves()
  if not (bridge_slaves) then
    log_warn(function()
      return {
        action = "bridge_slaves_fallback_master",
        bridge = bridge_ifname
      }
    end)
    bridge_slaves = {
      bridge_ifname
    }
  end
  log_info(function()
    return {
      action = "bridge_slaves_detected",
      count = #bridge_slaves,
      interfaces = table.concat(bridge_slaves, ",")
    }
  end)
  local workers_without_filter = {
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
  table.insert(workers_without_filter, {
    name = "events",
    pid = nil,
    restart_fn = function()
      return fork_worker("events", (function(fds)
        return require("worker_events").run(fds.rfd, fds.dir, fds.max_age_hours, fds.min_free_pct)
      end), {
        rfd = pipes.events.rfd,
        dir = config.events.dir or "/tmp/custos/events",
        max_age_hours = config.events.max_age_hours or 168,
        min_free_pct = config.events.min_free_pct or 30
      })
    end
  })
  table.insert(workers_without_filter, {
    name = "arp",
    pid = nil,
    restart_fn = function()
      return fork_worker("arp", function(wfd)
        return require("worker_arp_sniffer").run(bridge_slaves, wfd)
      end, pipes.learn.wfd)
    end
  })
  local auth_queue_num = tonumber(config.nfqueue.auth) or 5
  table.insert(workers_without_filter, {
    name = "auth-q",
    pid = nil,
    restart_fn = function()
      return fork_worker("auth-q", function(wfd)
        return require("worker_auth_queue").run(auth_queue_num, wfd)
      end, pipes.learn.wfd)
    end
  })
  for i, q_num in ipairs(captive_queues) do
    table.insert(workers_without_filter, {
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
    table.insert(workers_without_filter, {
      name = "rej-q" .. tostring(q_num),
      pid = nil,
      restart_fn = function()
        return fork_worker("rej-q" .. tostring(q_num), function(cfg)
          return require("worker_reject").run(q_num, cfg)
        end, auth_cfg)
      end
    })
  end
  if optional.sip then
    local sip_queue_num = tonumber(config.nfqueue.sip) or 12
    local sip_ack_info = alloc_ack_pipe()
    table.insert(workers_without_filter, {
      name = "sip",
      pid = nil,
      restart_fn = function()
        return fork_worker("sip", function(fds)
          return require("worker_sip").run(fds.q_num, fds)
        end, {
          q_num = sip_queue_num,
          nft_wfd = pipes.nft.wfd,
          ack_rfd = sip_ack_info.rfd,
          worker_idx = sip_ack_info.worker_idx
        })
      end
    })
  end
  table.insert(workers_without_filter, {
    name = "auth",
    pid = nil,
    restart_fn = function()
      return fork_worker("auth", function(cfg)
        return require("auth.worker").run_auth_worker(cfg)
      end, auth_cfg)
    end
  })
  for _index_0 = 1, #workers_without_filter do
    local w = workers_without_filter[_index_0]
    w.pid = w.restart_fn()
  end
  local nft_rules = require("nft_rules")
  nft_rules.apply()
  local rules_metadata = nft_rules.rules_metadata
  nft_extra.apply_from_config()
  filter.load()
  nft_rules.close()
  collectgarbage("collect")
  local filter_data = {
    rules = filter.rules,
    auth_cfg_cache = filter.auth_cfg_cache,
    sni_cfg_cache = filter.sni_cfg_cache,
    decision_cfg = filter.decision_cfg
  }
  local workers_with_filter = { }
  for i, q_num in ipairs(responses_queues) do
    local ack_info = alloc_ack_pipe()
    table.insert(workers_with_filter, {
      name = "resp-q" .. tostring(q_num),
      pid = nil,
      restart_fn = function()
        return fork_worker("resp-q" .. tostring(q_num), function(fds)
          return require("worker_responses").run(q_num, fds, rules_metadata)
        end, {
          question_response_rfd = pipes.question_response.rfd,
          nft_wfd = pipes.nft.wfd,
          ack_rfd = ack_info.rfd,
          worker_idx = ack_info.worker_idx
        })
      end
    })
  end
  table.insert(workers_with_filter, {
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
  for i, q_num in ipairs(questions_queues) do
    table.insert(workers_with_filter, {
      name = "dns-q" .. tostring(q_num),
      pid = nil,
      restart_fn = function()
        return fork_worker("dns-q" .. tostring(q_num), (function(fds)
          return require("worker_questions").run(q_num, fds.question_response_wfd, fds.learn_wfd, fds.events_wfd, filter_data)
        end), {
          question_response_wfd = pipes.question_response.wfd,
          learn_wfd = pipes.learn.wfd,
          events_wfd = pipes.events.wfd,
          filter_data = filter_data
        })
      end
    })
  end
  local sni_queue_num = tonumber(config.nfqueue.sni) or 6
  if optional.tls then
    table.insert(workers_with_filter, {
      name = "tls",
      pid = nil,
      restart_fn = function()
        return fork_worker("tls", function(fds)
          return require("worker_tls").run(tonumber(fds.q_num), fds.events_wfd, filter_data)
        end, {
          q_num = sni_queue_num,
          events_wfd = pipes.events.wfd,
          filter_data = filter_data
        })
      end
    })
  end
  local doh_cfg = load_doh_cfg()
  if optional.doh then
    doh_cfg.nft_wfd = pipes.nft.wfd
    local doh_ack_info = alloc_ack_pipe()
    doh_cfg.ack_rfd = doh_ack_info.rfd
    doh_cfg.worker_idx = doh_ack_info.worker_idx
    table.insert(workers_with_filter, {
      name = "doh",
      pid = nil,
      restart_fn = function()
        return fork_worker("doh", function(args)
          return require("worker_doh").run(args.cfg, args.filter_data)
        end, {
          cfg = doh_cfg,
          filter_data = filter_data
        })
      end
    })
  end
  for _index_0 = 1, #workers_with_filter do
    local w = workers_with_filter[_index_0]
    w.pid = w.restart_fn()
  end
  local workers = { }
  for _index_0 = 1, #workers_without_filter do
    local w = workers_without_filter[_index_0]
    table.insert(workers, w)
  end
  for _index_0 = 1, #workers_with_filter do
    local w = workers_with_filter[_index_0]
    table.insert(workers, w)
  end
  local status = ffi.new("int[1]")
  local siginfo = ffi.new("signalfd_siginfo")
  local sig_sz = ffi.sizeof("signalfd_siginfo")
  log_info(function()
    return {
      action = "supervisor_running",
      pid = tonumber(libc.getpid())
    }
  end)
  while true do
    local rv = libc.read(sfd, siginfo, sig_sz)
    if rv == sig_sz then
      if siginfo.ssi_signo == SIGHUP then
        log_info(function()
          return {
            action = "supervisor_sighup_reload"
          }
        end)
        filter.load()
        filter_data = {
          rules = filter.rules,
          auth_cfg_cache = filter.auth_cfg_cache,
          decision_cfg = filter.decision_cfg
        }
        for _index_0 = 1, #workers do
          local w = workers[_index_0]
          if (w.name:match("^dns%-q") or w.name:match("^resp%-q") or w.name:match("^cap%-q") or w.name:match("^rej%-q") or w.name == "doh" or w.name == "tls") and w.pid and w.pid > 0 then
            log_info(function()
              return {
                action = "supervisor_sighup_kill",
                name = w.name,
                pid = w.pid
              }
            end)
            libc.kill(w.pid, SIGTERM)
            status = ffi.new("int[1]")
            while libc.waitpid(w.pid, status, 0) ~= w.pid do
              local _ = nil
            end
            ffi.C.sleep(1)
            w.pid = w.restart_fn()
            log_info(function()
              return {
                action = "supervisor_sighup_refork",
                name = w.name,
                pid = w.pid
              }
            end)
          end
        end
        for _index_0 = 1, #workers do
          local w = workers[_index_0]
          if w.name == "auth" and w.pid and w.pid > 0 then
            log_info(function()
              return {
                action = "supervisor_sighup_forward_auth",
                pid = w.pid
              }
            end)
            libc.kill(w.pid, SIGHUP)
          end
        end
      else
        log_info(function()
          return {
            action = "supervisor_sigterm"
          }
        end)
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
          log_warn(function()
            return {
              action = "worker_died",
              name = w.name,
              pid = dead_pid,
              exit_code = exit_code
            }
          end)
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
log_info(function()
  return {
    action = "dns-filter_start",
    version = "1.0.0"
  }
end)
local cfg_meta = config.__meta or { }
log_info(function()
  return {
    action = "config_source",
    path = cfg_meta.path or "unknown",
    env_path = cfg_meta.env_path or "",
    external_loaded = cfg_meta.external_loaded and 1 or 0,
    load_error = cfg_meta.load_error or ""
  }
end)
if not (cfg_meta.external_loaded) then
  log_warn(function()
    return {
      action = "config_external_missing",
      path = cfg_meta.path or "unknown",
      detail = "running defaults (likely restrictive)"
    }
  end)
end
local sfd = create_signal_fd()
local pipes = create_pipes()
log_info(function()
  return {
    action = "ipc_pipes_created",
    question_response_rfd = pipes.question_response.rfd,
    question_response_wfd = pipes.question_response.wfd,
    learn_rfd = pipes.learn.rfd,
    learn_wfd = pipes.learn.wfd,
    events_rfd = pipes.events.rfd,
    events_wfd = pipes.events.wfd
  }
end)
return supervise(pipes, sfd)
