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
--   ├── worker_auth_queue   — capture trafic 33443, extrait MAC/IP, écrit vers AUTH
--   ├── worker AUTH          — portail HTTPS (lit pipe auth_ipc)
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
{ :probe_ipv6 } = require "doh.upstream"
{
  :SIGTERM, :SIGHUP, :WNOHANG
  :set_process_name
  :fork_worker
  :shutdown_workers
} = require "lib.process"

-- Renomme le processus superviseur pour qu'il apparaisse comme "custos"
-- dans ps, logread et syslog (au lieu de "luajit" ou "luajit2").
set_process_name "custos"

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

--- Crée les trois pipes utilisés par Custos.
-- q0q1 : transactions DNS Q0 → Q1.
-- learn : apprentissage IP→MAC Q0 → mac_learner.
-- events : événements DNS Q0 → worker_events.
-- nft : serialized dynamic nft insertions.
-- @treturn table {q0q1, learn, events}
create_pipes = ->
  {
    q0q1:   create_pipe "q0q1"
    learn:  create_pipe "mac_learn"
    events: create_pipe "events"
    nft:    create_pipe "nft"
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
  auth.session_ttl        = auth.session_ttl        or 0
  auth.secrets            = auth.secrets            or "/etc/custos/secrets"
  auth.sessions_file      = auth.sessions_file      or "./tmp/sessions.lua"

  auth

-- ── Configuration DoH ──────────────────────────────────────────

--- Build the doh_cfg table from config constants.
-- @treturn table doh_cfg
load_doh_cfg = ->
  {
    enabled:      config.DOH_ENABLED == "1"
    port:         tonumber(config.DOH_PORT) or 8443
    upstream_ip:  do
      if config.DOH_PREFER_IPV6 == "1" and probe_ipv6 config.DOH_UPSTREAM_IPV6
        config.DOH_UPSTREAM_IPV6
      else
        config.DOH_UPSTREAM_IPV4
    upstream_port: tonumber(config.DOH_UPSTREAM_PORT) or 53
    timeout_ms:   tonumber(config.DOH_UPSTREAM_TIMEOUT_MS) or 2000
    cert_path:    if config.DOH_CERT_PATH and #config.DOH_CERT_PATH > 0 then config.DOH_CERT_PATH else nil
    key_path:     if config.DOH_KEY_PATH  and #config.DOH_KEY_PATH  > 0 then config.DOH_KEY_PATH  else nil
  }

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
    if pipes.events
      libc.close pipes.events.rfd if pipes.events.rfd
      libc.close pipes.events.wfd if pipes.events.wfd
    if pipes.nft
      libc.close pipes.nft.rfd if pipes.nft.rfd
      libc.close pipes.nft.wfd if pipes.nft.wfd
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

  -- Nom de l'interface bridge : requis pour mac_learner (prober ARP/NS)
  -- et arp-sniffer. Déclaré avant `workers` pour que les closures puissent le capturer.
  bridge_ifname = auth_cfg.bridge_ifname or os.getenv("BRIDGE_IFNAME") or "br"

  -- Autodétection des interfaces physiques attachées à la bridge (bridge slaves)
  -- pour le sniffer TCP/33443. Ces interfaces physiques voient les paquets entrants,
  -- contrairement à la bridge elle-même qui ne voit pas les paquets traités localement.
  detect_bridge_slaves = () ->
    handle = io.popen "ip -brief link show type bridge_slave 2>/dev/null"
    return nil unless handle
    slaves = {}
    for line in handle\lines()
      ifname = line\match "^(%S+)"
      table.insert slaves, ifname if ifname
    handle\close()
    #slaves > 0 and slaves or nil

  bridge_slaves = detect_bridge_slaves() or { bridge_ifname }
  log_info {
    action: "bridge_slaves_detected"
    count: #bridge_slaves
    interfaces: table.concat(bridge_slaves, ",")
  }

  workers = {
    {
      name: "mac-lrn"
      pid: nil
      restart_fn: -> fork_worker "mac-lrn",
          (rfd) -> require("mac_learner").run rfd, bridge_ifname,
          pipes.learn.rfd
    }
  }

  table.insert workers, {
    name: "nft"
    pid: nil
    restart_fn: -> fork_worker "nft",
      (rfd) -> require("worker_nft").run rfd,
      pipes.nft.rfd
  }

  table.insert workers, {
    name: "events"
    pid: nil
    restart_fn: -> fork_worker "events",
      ((fds) -> require("worker_events").run fds.rfd, fds.dir, fds.max_age_hours, fds.min_free_pct),
      { rfd: pipes.events.rfd, dir: config.EVENTS_DIR or "/tmp/custos/events",
        max_age_hours: config.EVENTS_MAX_AGE_HOURS or 168,
        min_free_pct:  config.EVENTS_MIN_FREE_PCT  or 30 }
  }

  -- Worker passif ARP/NDP : apprend les associations IP→MAC pour tous les VLANs
  -- en sniffant les trames ARP et les messages NDP NS/NA sur le bridge.
  table.insert workers, {
    name: "arp"
    pid: nil
    restart_fn: -> fork_worker "arp",
      (wfd) -> require("worker_arp_sniffer").run bridge_ifname, wfd,
      pipes.learn.wfd
  }

  -- Worker NFQUEUE hybride pour l'authentification
  -- Écrit dans le pipe 'learn' pour alimenter le mac_learner
  auth_queue_num = tonumber(config.QUEUE_AUTH) or 5
  table.insert workers, {
    name: "auth-q"
    pid: nil
    restart_fn: -> fork_worker "auth-q",
      (wfd) -> require("worker_auth_queue").run auth_queue_num, wfd,
      pipes.learn.wfd
  }

  -- Multiple workers for questions (parallel Q0)
  for i, q_num in ipairs questions_queues
    table.insert workers, {
      name: "dns-q#{q_num}"
      pid: nil
      restart_fn: -> fork_worker "dns-q#{q_num}",
        ((fds) -> require("worker_questions").run q_num, fds.q0q1_wfd, fds.learn_wfd, fds.events_wfd),
        { q0q1_wfd: pipes.q0q1.wfd, learn_wfd: pipes.learn.wfd, events_wfd: pipes.events.wfd }
    }

  -- Multiple workers for responses (parallel Q1)
  for i, q_num in ipairs responses_queues
    table.insert workers, {
      name: "resp-q#{q_num}"
      pid: nil
      restart_fn: -> fork_worker "resp-q#{q_num}",
        (fds) -> require("worker_responses").run q_num, fds,
        { q0q1_rfd: pipes.q0q1.rfd, nft_wfd: pipes.nft.wfd }
    }

  -- Multiple workers for captive (parallel Q2)
  for i, q_num in ipairs captive_queues
    table.insert workers, {
      name: "cap-q#{q_num}"
      pid: nil
      restart_fn: -> fork_worker "cap-q#{q_num}",
        (cfg) -> require("worker_captive").run q_num, cfg,
        auth_cfg
    }

  -- Multiple workers for reject (parallel Q3)
  for i, q_num in ipairs reject_queues
    table.insert workers, {
      name: "rej-q#{q_num}"
      pid: nil
      restart_fn: -> fork_worker "rej-q#{q_num}",
        (cfg) -> require("worker_reject").run q_num, cfg,
        auth_cfg
    }

  -- AUTH (single).
  -- Utilise mac_learner_ipc (get_mac) pour obtenir la MAC de manière fiable.
  table.insert workers, {
    name: "auth"
    pid: nil
    restart_fn: -> fork_worker "auth",
      (cfg) -> require("auth.worker").run_auth_worker cfg,
      auth_cfg
  }

  -- DoH worker (single, optional). Only forked when DOH_ENABLED == "1".
  doh_cfg = load_doh_cfg!
  if doh_cfg.enabled
    doh_cfg.nft_wfd = pipes.nft.wfd
    table.insert workers, {
      name: "doh"
      pid: nil
      restart_fn: -> fork_worker "doh",
        (cfg) -> require("worker_doh").run cfg,
        doh_cfg
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

        -- Kill + refork all Q0/Q1/Q2/Q3/DOH workers to refresh COW filter lists
        for w in *workers
          if (w.name\match("^questions%-q") or w.name\match("^responses%-q") or w.name\match("^captive%-q") or w.name\match("^reject%-q") or w.name == "DOH") and w.pid and w.pid > 0
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
  events_rfd: pipes.events.rfd
  events_wfd: pipes.events.wfd
}

supervise pipes, sfd
