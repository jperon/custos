-- src/main.moon
-- Superviseur principal : crée les pipes IPC, fork les workers,
-- surveille les processus enfants et les relance en cas de crash.
--
-- Architecture des processus :
--
--   main (superviseur)
--   ├── mac_learner          — lit pipe learn Q0→learner, répond socket Unix
--   ├── worker Q0 questions  — écrit Q0→Q1 et Q0→mac_learner
--   ├── worker Q1 réponses   — lit Q0→Q1
--   ├── worker AUTH          — portail HTTPS
--   ├── worker Q2 captif     — mode bridge
--   └── worker Q3 reject     — mode bridge
--
-- Le superviseur ne traite aucun paquet. Il boucle sur waitpid()
-- et relance le worker mort après un délai de 1 seconde.
--
-- Shutdown propre sur SIGTERM :
--   • SIGTERM est masqué et capturé via signalfd (pas de handler C async)
--   • Sur réception : SIGTERM envoyé aux workers → waitpid() → exit(0)
--   • Garantit que les queues NFQUEUE sont libérées avant que procd
--     lance la nouvelle instance.
--
-- Rechargement à chaud sur SIGHUP :
--   • SIGHUP est masqué et capturé via le même signalfd
--   • Sur réception : SIGHUP propagé à Q0 et AUTH.

{ :ffi, :libc } = require "ffi_defs"
{ :log_info, :log_warn } = require "log"
{
  :SIGTERM, :SIGHUP, :WNOHANG
  :fork_worker
  :shutdown_workers
} = require "lib.process"

bit = require "bit"
config = require "config"
filter = require "filter"
nft_rules = require "nft_rules"
nft_extra = require "nft_extra_rules"

-- ── Helpers POSIX ────────────────────────────────────────────────

ffi.cdef [[
  unsigned int sleep(unsigned int seconds);
]]

SIG_BLOCK     = 0
O_NONBLOCK    = 2048
F_SETPIPE_SZ  = 1031
PIPE_DESIRED_SIZE = 65536

-- ── signalfd pour SIGTERM + SIGHUP ───────────────────────────────

--- Crée un signalfd non-bloquant pour SIGTERM et SIGHUP.
-- @treturn number fd du signalfd
-- @raise string si signalfd échoue
create_signal_fd = ->
  mask = ffi.new "sigset_t_custos"
  ffi.fill mask, ffi.sizeof(mask), 0

  word = ffi.cast "uint32_t*", mask
  word[0] = bit.bor word[0], bit.lshift(1, SIGTERM - 1)
  word[0] = bit.bor word[0], bit.lshift(1, SIGHUP  - 1)

  libc.sigprocmask SIG_BLOCK, mask, nil

  fd = libc.signalfd -1, mask, O_NONBLOCK
  error "signalfd() échoué" if fd < 0
  fd

-- ── Création des pipes IPC ───────────────────────────────────────

--- Crée un pipe non-bloquant et tente d'augmenter sa capacité.
-- @tparam string name Nom logique du pipe pour les logs
-- @treturn table {rfd, wfd}
-- @raise string si pipe2 échoue
create_pipe = (name) ->
  fds = ffi.new "int[2]"

  rc = libc.pipe2 fds, O_NONBLOCK
  error "pipe2() échoué pour #{name}" if rc != 0

  sz = libc.fcntl fds[1], F_SETPIPE_SZ, PIPE_DESIRED_SIZE
  if sz and sz >= 0
    log_info { action: "pipe_resize", name: name, fd: fds[1], new_size: sz }
  else
    log_warn { action: "pipe_resize_failed", name: name, fd: fds[1], rc: sz }

  { rfd: fds[0], wfd: fds[1] }

--- Crée les deux pipes utilisés par Custos.
-- q0q1 : transactions DNS Q0 → Q1.
-- learn : apprentissage IP→MAC Q0 → mac_learner.
-- @treturn table {q0q1, learn}
create_pipes = ->
  {
    q0q1: create_pipe "q0q1"
    learn: create_pipe "mac_learn"
  }

-- ── Configuration AUTH ───────────────────────────────────────────

--- Charge la configuration auth avec les valeurs par défaut nécessaires.
-- @treturn table Configuration auth
load_auth_cfg = ->
  { :load_config } = require "filter.lib.load_config"

  filter_cfg, cfg_err = load_config os.getenv("CUSTOS_FILTER_CONFIG") or "/etc/custos/filter.yml"
  unless filter_cfg
    log_warn { action: "auth_cfg_load_warning", err: cfg_err }
    filter_cfg = { auth: {} }

  auth = filter_cfg.auth or {}
  auth.port               = auth.port               or 33443
  auth.idle_timeout       = auth.idle_timeout       or 120
  auth.heartbeat_interval = auth.heartbeat_interval or 30
  auth.session_ttl        = auth.session_ttl        or 3600
  auth.secrets            = auth.secrets            or "/etc/custos/secrets"
  auth.sessions_file      = auth.sessions_file      or "./tmp/sessions.lua"

  auth

-- ── Shutdown explicite des workers ───────────────────────────────

--- Ferme les fd de pipes encore détenus par le superviseur.
-- @tparam table pipes Table retournée par create_pipes()
-- @treturn nil
close_supervisor_fds = (pipes) ->
  if pipes
    if pipes.q0q1
      libc.close pipes.q0q1.rfd if pipes.q0q1.rfd
      libc.close pipes.q0q1.wfd if pipes.q0q1.wfd
    if pipes.learn
      libc.close pipes.learn.rfd if pipes.learn.rfd
      libc.close pipes.learn.wfd if pipes.learn.wfd
  nil

-- ── Boucle de supervision ────────────────────────────────────────

--- Supervise les workers, les relance en cas de crash,
-- et arrête proprement l'ensemble sur SIGTERM.
-- @tparam table pipes Pipes IPC
-- @tparam number sfd fd du signalfd écoutant SIGTERM/SIGHUP
-- @treturn nil
supervise = (pipes, sfd) ->
  auth_cfg = load_auth_cfg!

  -- Parse queue lists from config, supporting single numbers and ranges (e.g. "0,2,5-7,10-12")
  parse_queues = (str) ->
    queues = {}
    for part in str\gmatch "%d+%-?%d*"
      if part\match "%-%d+" then
        a, b = part\match "(%d+)%-(%d+)"
        a, b = tonumber(a), tonumber(b)
        if a and b then
          if a <= b then
            for n = a, b do table.insert queues, n
          else
            for n = b, a do table.insert queues, n
        else
          -- fallback: treat as single
          n = tonumber(part)
          if n then table.insert queues, n
      else
        n = tonumber(part)
        if n then table.insert queues, n
    queues

  questions_queues = parse_queues config.QUEUE_QUESTIONS
  responses_queues = parse_queues config.QUEUE_RESPONSES
  captive_queues   = parse_queues config.QUEUE_CAPTIVE
  reject_queues    = parse_queues config.QUEUE_REJECT

  workers = {
    {
      name: "MAC-learner"
      pid: nil
      restart_fn: -> fork_worker "MAC-learner",
        (rfd) -> require("mac_learner").run rfd,
        pipes.learn.rfd
    }
  }

  -- Multiple workers for questions (parallel Q0)
  for i, q_num in ipairs questions_queues
    table.insert workers, {
      name: "questions-q#{q_num}"
      pid: nil
      restart_fn: -> fork_worker "questions-q#{q_num}",
        ((fds) -> require("worker_questions").run q_num, fds.q0q1_wfd, fds.learn_wfd),
        { q0q1_wfd: pipes.q0q1.wfd, learn_wfd: pipes.learn.wfd }
    }

  -- Multiple workers for responses (parallel Q1)
  for i, q_num in ipairs responses_queues
    table.insert workers, {
      name: "responses-q#{q_num}"
      pid: nil
      restart_fn: -> fork_worker "responses-q#{q_num}",
        (rfd) -> require("worker_responses").run q_num, rfd,
        pipes.q0q1.rfd
    }

  -- Multiple workers for captive (parallel Q2)
  for i, q_num in ipairs captive_queues
    table.insert workers, {
      name: "captive-q#{q_num}"
      pid: nil
      restart_fn: -> fork_worker "captive-q#{q_num}",
        (cfg) -> require("worker_captive").run q_num, cfg,
        auth_cfg
    }

  -- Multiple workers for reject (parallel Q3)
  for i, q_num in ipairs reject_queues
    table.insert workers, {
      name: "reject-q#{q_num}"
      pid: nil
      restart_fn: -> fork_worker "reject-q#{q_num}",
        (cfg) -> require("worker_reject").run q_num, cfg,
        auth_cfg
    }

  -- AUTH (single)
  table.insert workers, {
    name: "AUTH"
    pid: nil
    restart_fn: -> fork_worker "AUTH",
      (cfg) -> require("auth.worker").run_auth_worker cfg,
      auth_cfg
  }

  -- Apply main nftables ruleset (with queue numbers and timeouts from config).
  nft_rules.apply!

  -- Load filter rules before forking so workers inherit via COW.
  filter.load!

  -- Apply extra nft rules before forking workers, so the bypass is in place
  -- before any queue starts intercepting traffic.
  nft_extra.apply_from_config!

  for w in *workers
    w.pid = w.restart_fn!

  status  = ffi.new "int[1]"
  siginfo = ffi.new "signalfd_siginfo"
  sig_sz  = ffi.sizeof "signalfd_siginfo"

  log_info { action: "supervisor_running", pid: tonumber libc.getpid! }

  while true
    rv = libc.read sfd, siginfo, sig_sz
    if rv == sig_sz
      if siginfo.ssi_signo == SIGHUP
        log_info { action: "supervisor_sighup_reload" }
        filter.load!

        -- Kill + refork all Q0/Q1/Q2/Q3 workers to refresh COW lists
        for w in *workers
          if (w.name\match("^questions%-q") or w.name\match("^responses%-q") or w.name\match("^captive%-q") or w.name\match("^reject%-q")) and w.pid and w.pid > 0
            log_info { action: "supervisor_sighup_kill", name: w.name, pid: w.pid }
            libc.kill w.pid, SIGTERM
            status = ffi.new "int[1]"
            while libc.waitpid(w.pid, status, 0) ~= w.pid do nil
            ffi.C.sleep 1
            w.pid = w.restart_fn!
            log_info { action: "supervisor_sighup_refork", name: w.name, pid: w.pid }

        -- Forward SIGHUP to AUTH only (secrets reload)
        for w in *workers
          if w.name == "AUTH" and w.pid and w.pid > 0
            log_info { action: "supervisor_sighup_forward_auth", pid: w.pid }
            libc.kill w.pid, SIGHUP
      else
        log_info { action: "supervisor_sigterm" }
        nft_extra.cleanup!
        shutdown_workers workers
        close_supervisor_fds pipes
        libc._exit 0

    dead_pid = tonumber libc.waitpid -1, status, WNOHANG
    if dead_pid and dead_pid > 0
      for w in *workers
        if w.pid == dead_pid
          exit_code = bit.rshift bit.band(status[0], 0xFF00), 8
          log_warn {
            action: "worker_died"
            name: w.name
            pid: dead_pid
            exit_code: exit_code
          }
          ffi.C.sleep 1
          w.pid = w.restart_fn!
          break
    else
      ffi.C.sleep 1

-- ── main ─────────────────────────────────────────────────────────

log_info { action: "dns-filter_start", version: "1.0.0" }

sfd   = create_signal_fd!
pipes = create_pipes!

log_info {
  action: "ipc_pipes_created"
  q0q1_rfd: pipes.q0q1.rfd
  q0q1_wfd: pipes.q0q1.wfd
  learn_rfd: pipes.learn.rfd
  learn_wfd: pipes.learn.wfd
}

supervise pipes, sfd
