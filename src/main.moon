-- src/main.moon
-- Superviseur principal : crée les pipes IPC, fork les workers,
-- surveille les processus enfants et les relance en cas de crash.
--
-- Architecture des processus :
--
--   main (superviseur)
--   ├── mac_learner          — lit pipe learn question→learner, répond socket Unix
--   ├── worker question            — écrit question→response et question→mac_learner
--   ├── worker response            — lit question→response
--   ├── worker_auth_queue   — capture trafic 33443, extrait MAC/IP, écrit vers AUTH
--   ├── worker AUTH          — portail HTTPS (lit pipe auth_ipc)
--   ├── worker captive             — mode bridge
--   └── worker reject              — mode bridge
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
--   • Sur réception : SIGHUP propagé à question et AUTH.

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
    errno = tonumber(ffi.C.__errno_location()[0])
    log_warn { action: "pipe_resize_failed", name: name, fd: fds[1], rc: sz, errno: errno }

  { rfd: fds[0], wfd: fds[1] }

--- Crée les trois pipes utilisés par Custos.
-- question_response : transactions DNS question → response.
-- learn : apprentissage IP→MAC question → mac_learner.
-- events : événements DNS question → worker_events.
-- nft : serialized dynamic nft insertions.
-- @treturn table {question_response, learn, events}
create_pipes = ->
  {
    question_response:   create_pipe "question_response"
    learn:  create_pipe "mac_learn"
    events: create_pipe "events"
    nft:    create_pipe "nft"
  }

-- ── Configuration AUTH ───────────────────────────────────────────

--- Charge la configuration auth avec les valeurs par défaut nécessaires.
-- @treturn table Configuration auth
load_auth_cfg = ->
  auth = {}
  for k, v in pairs(config.auth or {})
    auth[k] = v
  auth.port               = tonumber(auth.port) or 33443
  auth.idle_timeout       = tonumber(auth.idle_timeout) or 120
  auth.heartbeat_interval = tonumber(auth.heartbeat_interval) or 30
  auth.session_ttl        = tonumber(auth.session_ttl) or 0
  auth.secrets            = auth.secrets or "/etc/custos/secrets"
  auth.sessions_file      = auth.sessions_file or "/tmp/sessions.lua"
  auth

-- ── Configuration DoH ──────────────────────────────────────────

--- Build the doh_cfg table from config constants.
-- @treturn table doh_cfg
load_doh_cfg = ->
  {
    enabled:      config.doh.enabled
    port:         tonumber(config.doh.port) or 8443
    upstream_ip:  do
      if config.doh.prefer_ipv6 and probe_ipv6 config.doh.upstream_ipv6
        config.doh.upstream_ipv6
      else
        config.doh.upstream_ipv4
    upstream_port: tonumber(config.doh.upstream_port) or 53
    timeout_ms:   tonumber(config.doh.upstream_timeout_ms) or 2000
    cert_path:    if config.doh.cert_path and #config.doh.cert_path > 0 then config.doh.cert_path else nil
    key_path:     if config.doh.key_path  and #config.doh.key_path  > 0 then config.doh.key_path  else nil
  }

-- ── Shutdown explicite des workers ───────────────────────────────

--- Ferme les fd de pipes encore détenus par le superviseur.
-- @tparam table pipes Table retournée par create_pipes()
-- @treturn nil
close_supervisor_fds = (pipes) ->
  if pipes
    if pipes.question_response
      libc.close pipes.question_response.rfd if pipes.question_response.rfd
      libc.close pipes.question_response.wfd if pipes.question_response.wfd
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

  questions_queues = parse_queues config.nfqueue.questions
  responses_queues = parse_queues config.nfqueue.responses
  captive_queues   = parse_queues config.nfqueue.captive
  reject_queues    = parse_queues config.nfqueue.reject

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

  -- ── Pipes ACK nft (un par worker_responses + un pour DoH) ──────
  -- Chaque pipe est dédié à un worker ; worker_nft écrit 1 octet d'ACK
  -- après chaque flush de batch, avant que le worker rende son verdict DNS.
  -- worker_idx est 0-based ; le tableau ack_wfds est 1-indexed côté Lua.
  ack_pipes  = {}  -- liste de {rfd, wfd} créés ici
  ack_wfds   = {}  -- tableau des wfd passés à worker_nft (1-indexed)
  next_widx  = 0   -- compteur d'attribution des worker_idx

  alloc_ack_pipe = ->
    p = create_pipe "ack_#{next_widx}"
    ack_pipes[#ack_pipes + 1] = p
    ack_wfds[next_widx + 1]   = p.wfd   -- 1-indexed pour le tableau Lua
    widx = next_widx
    next_widx += 1
    { rfd: p.rfd, worker_idx: widx }

  table.insert workers, {
    name: "nft"
    pid: nil
    -- La restart_fn capture ack_wfds par référence ; si worker_nft redémarre,
    -- il reçoit le même tableau (les pipes ACK restent ouverts).
    restart_fn: -> fork_worker "nft",
      (args) -> require("worker_nft").run args.rfd, args.ack_wfds,
      { rfd: pipes.nft.rfd, ack_wfds: ack_wfds }
  }

  table.insert workers, {
      name: "events"
      pid: nil
      restart_fn: -> fork_worker "events",
        ((fds) -> require("worker_events").run fds.rfd, fds.dir, fds.max_age_hours, fds.min_free_pct),
        { rfd: pipes.events.rfd, dir: config.events.dir or "/tmp/custos/events",
          max_age_hours: config.events.max_age_hours or 168,
          min_free_pct:  config.events.min_free_pct  or 30 }
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
  auth_queue_num = tonumber(config.nfqueue.auth) or 5
  table.insert workers, {
    name: "auth-q"
    pid: nil
    restart_fn: -> fork_worker "auth-q",
      (wfd) -> require("worker_auth_queue").run auth_queue_num, wfd,
      pipes.learn.wfd
  }

  -- Multiple workers for questions (parallel question)
  for i, q_num in ipairs questions_queues
    table.insert workers, {
      name: "dns-q#{q_num}"
      pid: nil
      restart_fn: -> fork_worker "dns-q#{q_num}",
        ((fds) -> require("worker_questions").run q_num, fds.question_response_wfd, fds.learn_wfd, fds.events_wfd),
        { question_response_wfd: pipes.question_response.wfd, learn_wfd: pipes.learn.wfd, events_wfd: pipes.events.wfd }
    }

  -- Multiple workers for responses (parallel response)
  -- Chaque worker_responses reçoit un pipe ACK dédié pour la synchronisation nft.
  for i, q_num in ipairs responses_queues
    ack_info = alloc_ack_pipe!
    table.insert workers, {
      name: "resp-q#{q_num}"
      pid: nil
      restart_fn: -> fork_worker "resp-q#{q_num}",
        (fds) -> require("worker_responses").run q_num, fds,
        { question_response_rfd: pipes.question_response.rfd, nft_wfd: pipes.nft.wfd,
          ack_rfd: ack_info.rfd, worker_idx: ack_info.worker_idx }
    }

  -- Multiple workers for captive (parallel captive)
  for i, q_num in ipairs captive_queues
    table.insert workers, {
      name: "cap-q#{q_num}"
      pid: nil
      restart_fn: -> fork_worker "cap-q#{q_num}",
        (cfg) -> require("worker_captive").run q_num, cfg,
        auth_cfg
    }

  -- Multiple workers for reject (parallel reject)
  for i, q_num in ipairs reject_queues
    table.insert workers, {
      name: "rej-q#{q_num}"
      pid: nil
      restart_fn: -> fork_worker "rej-q#{q_num}",
        (cfg) -> require("worker_reject").run q_num, cfg,
        auth_cfg
    }

  -- SNI logger for TLS/QUIC (single, optional).
  -- Captures TCP/443 SYN (TLS ClientHello) and UDP/443 (QUIC Initial) packets.
  sni_queue_num = tonumber(config.nfqueue.sni_log) or 6
  if config.nfqueue.sni_log
    table.insert workers, {
      name: "tls-log"
      pid: nil
      restart_fn: -> fork_worker "tls-log",
        (fds) -> require("worker_tls").run tonumber(fds.q_num), fds.events_wfd,
        { q_num: sni_queue_num, events_wfd: pipes.events.wfd }
    }

  -- SIP/STUN worker (single, optional).
  -- Whitelists proxy IPs and SDP media IPs in per-rule sets.
  if config.nfqueue.sip
    sip_queue_num = tonumber(config.nfqueue.sip) or 12
    sip_ack_info  = alloc_ack_pipe!
    table.insert workers, {
      name: "sip"
      pid: nil
      restart_fn: -> fork_worker "sip",
        (fds) -> require("worker_sip").run fds.q_num, fds,
        { q_num: sip_queue_num, nft_wfd: pipes.nft.wfd,
          ack_rfd: sip_ack_info.rfd, worker_idx: sip_ack_info.worker_idx }
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
    -- Allouer un pipe ACK dédié au worker DoH.
    doh_ack_info     = alloc_ack_pipe!
    doh_cfg.ack_rfd    = doh_ack_info.rfd
    doh_cfg.worker_idx = doh_ack_info.worker_idx
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

        -- Kill + refork all question/response/captive/reject/DOH workers to refresh COW filter lists
        for w in *workers
          if (w.name\match("^dns%-q") or w.name\match("^resp%-q") or w.name\match("^cap%-q") or w.name\match("^rej%-q") or w.name == "doh") and w.pid and w.pid > 0
            log_info { action: "supervisor_sighup_kill", name: w.name, pid: w.pid }
            libc.kill w.pid, SIGTERM
            status = ffi.new "int[1]"
            while libc.waitpid(w.pid, status, 0) ~= w.pid do nil
            ffi.C.sleep 1
            w.pid = w.restart_fn!
            log_info { action: "supervisor_sighup_refork", name: w.name, pid: w.pid }

        -- Forward SIGHUP to AUTH only (secrets reload)
        for w in *workers
          if w.name == "auth" and w.pid and w.pid > 0
            log_info { action: "supervisor_sighup_forward_auth", pid: w.pid }
            libc.kill w.pid, SIGHUP
      else
        log_info { action: "supervisor_sigterm" }
        nft_extra.cleanup!
        shutdown_workers workers
        close_supervisor_fds pipes
        -- Ferme les pipes ACK côté superviseur (les enfants ont déjà quitté).
        for p in *ack_pipes
          libc.close p.rfd
          libc.close p.wfd
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
cfg_meta = config.__meta or {}
log_info {
  action: "config_source"
  path: cfg_meta.path or "unknown"
  env_path: cfg_meta.env_path or ""
  external_loaded: cfg_meta.external_loaded and 1 or 0
  load_error: cfg_meta.load_error or ""
}
unless cfg_meta.external_loaded
  log_warn {
    action: "config_external_missing"
    path: cfg_meta.path or "unknown"
    detail: "running defaults (likely restrictive)"
  }

sfd   = create_signal_fd!
pipes = create_pipes!

log_info {
  action: "ipc_pipes_created"
  question_response_rfd: pipes.question_response.rfd
  question_response_wfd: pipes.question_response.wfd
  learn_rfd: pipes.learn.rfd
  learn_wfd: pipes.learn.wfd
  events_rfd: pipes.events.rfd
  events_wfd: pipes.events.wfd
}

supervise pipes, sfd
