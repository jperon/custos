-- src/main.moon
-- Superviseur principal : crée le pipe IPC, fork les deux workers,
-- surveille les processus enfants et les relance en cas de crash.
--
-- Architecture des processus :
--
--   main (superviseur)
--   ├── worker Q0 (questions)   — écrit dans pipe_wfd
--   └── worker Q1 (réponses)   — lit depuis pipe_rfd
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
--   • Sur réception : SIGHUP propagé à Q0 (qui recharge la config filtre
--     + la liste blanche IP via filter.reload())

{ :ffi, :libc } = require "ffi_defs"
{ :log_info, :log_warn, :log_error } = require "log"

-- ── Helpers POSIX ────────────────────────────────────────────────
ffi.cdef [[
  unsigned int sleep(unsigned int seconds);
  int getpid(void);
]]

WNOHANG = 1
SIGTERM = 15
SIGHUP  = 1

-- ── signalfd pour SIGTERM + SIGHUP ───────────────────────────────
-- Masque SIGTERM et SIGHUP et les expose comme fd lisible ; évite
-- tout callback C async qui pourrait ré-entrer dans le VM LuaJIT.
-- SIGHUP est capturé ici pour être propagé aux workers (en
-- particulier Q0 qui gère le rechargement de la config filtre).
--
-- sigset_t sur Linux = 128 octets ; SIGTERM=15 → bit 14, SIGHUP=1 → bit 0.
create_signal_fd = ->
  SIG_BLOCK = 0
  mask = ffi.new "sigset_t_custos"
  ffi.fill mask, ffi.sizeof(mask), 0
  word = ffi.cast "uint32_t*", mask
  word[0] = bit.bor word[0], bit.lshift(1, SIGTERM - 1)
  word[0] = bit.bor word[0], bit.lshift(1, SIGHUP  - 1)
  libc.sigprocmask SIG_BLOCK, mask, nil
  -- SFD_NONBLOCK=2048 pour que read() soit non-bloquant dans la boucle
  fd = libc.signalfd -1, mask, 2048
  error "signalfd() échoué" if fd < 0
  fd

-- ── Création du pipe IPC ─────────────────────────────────────────
create_pipe = ->
  fds = ffi.new "int[2]"
  -- pipe2 avec O_NONBLOCK (2048) sur le fd de lecture pour que drain_pipe()
  -- dans Q1 soit non-bloquant. Plus fiable que pipe+fcntl avec LuaJIT FFI.
  rc = libc.pipe2 fds, 2048
  error "pipe2() échoué" if rc != 0
  { rfd: fds[0], wfd: fds[1] }

-- ── Fork d'un worker ─────────────────────────────────────────────
--- Fork et lance un worker dans le processus enfant.
-- @tparam string name  Nom du worker (pour les logs)
-- @tparam function worker_fn  Fonction à appeler dans l'enfant
-- @tparam number pipe_fd  fd du pipe IPC à passer au worker
-- @treturn number pid de l'enfant (dans le parent uniquement)
fork_worker = (name, worker_fn, pipe_fd) ->
  parent_pid = tonumber libc.getpid!
  pid = libc.fork!

  if pid < 0
    error "fork() échoué pour #{name}"

  if pid == 0
    -- ── Processus enfant ───────────────────────────────────────
    -- Le superviseur a bloqué SIGTERM et SIGHUP via sigprocmask (pour
    -- signalfd). Ce masque est hérité par fork() : il faut les débloquer
    -- ici, sinon prctl(PR_SET_PDEATHSIG) et kill(SIGTERM/SIGHUP) resteraient
    -- sans effet.
    unmask = ffi.new "sigset_t_custos"
    ffi.fill unmask, ffi.sizeof(unmask), 0
    uword = ffi.cast "uint32_t*", unmask
    uword[0] = bit.bor(bit.lshift(1, SIGTERM - 1), bit.lshift(1, SIGHUP - 1))
    libc.sigprocmask 1, unmask, nil        -- SIG_UNBLOCK=1
    -- PR_SET_PDEATHSIG : filet de sécurité si le superviseur meurt
    -- brutalement (avant que shutdown_workers ait pu envoyer SIGTERM).
    if libc.prctl(1, SIGTERM, 0, 0, 0) != 0
      log_error { action: "prctl_failed", name: name }
      libc._exit 1
    -- Si le parent est déjà mort entre fork() et prctl(), exit immédiat
    if tonumber(libc.getppid!) != parent_pid
      libc._exit 0
    worker_fn pipe_fd
    libc._exit 0
    -- _exit() ne retourne jamais

  -- ── Processus parent ───────────────────────────────────────────
  log_info { action: "worker_started", name: name, pid: tonumber pid }
  pid

-- ── Shutdown explicite des workers ───────────────────────────────
--- Envoie SIGTERM à tous les workers et attend leur sortie complète.
-- Appelé sur réception de SIGTERM par le superviseur pour garantir
-- que les queues NFQUEUE sont libérées avant la fin du processus.
-- @tparam table workers  Table des workers { name, pid, ... }
shutdown_workers = (workers) ->
  for w in *workers
    if w.pid and w.pid > 0
      log_info { action: "worker_stopping", name: w.name, pid: w.pid }
      libc.kill w.pid, SIGTERM
  status = ffi.new "int[1]"
  dead = libc.waitpid -1, status, 0
  while dead > 0
    dead = libc.waitpid -1, status, 0

-- ── Boucle de supervision ────────────────────────────────────────
--- Supervise les workers Q0, Q1 et AUTH, les relance en cas de crash,
-- et arrête proprement l'ensemble sur SIGTERM.
-- @tparam table pipe  { rfd, wfd } du pipe IPC
-- @tparam number sfd  fd du signalfd écoutant SIGTERM
supervise = (pipe, sfd) ->
  -- Charge la configuration pour transmettre auth_cfg au worker AUTH.
  -- On utilise load_config ici (dans le parent, avant fork) pour que
  -- le worker auth dispose de la section auth dès le démarrage.
  { :load_config } = require "filter.lib.load_config"
  filter_cfg, cfg_err = load_config os.getenv("CUSTOS_FILTER_CONFIG") or "cfg/filter.yml"
  if not filter_cfg
    log_warn { action: "auth_cfg_load_warning", err: cfg_err }
    filter_cfg = { auth: {} }
  auth_cfg = filter_cfg.auth or {}

  workers = {
    {
      name:       "Q0-questions"
      pid:        nil
      restart_fn: -> fork_worker "Q0-questions", (-> require("worker_q0").run pipe.wfd), pipe.wfd
    }
    {
      name:       "Q1-responses"
      pid:        nil
      restart_fn: -> fork_worker "Q1-responses", (-> require("worker_q1").run pipe.rfd), pipe.rfd
    }
    {
      name:       "AUTH"
      pid:        nil
      -- Le worker AUTH n'utilise pas le pipe DNS ; on passe pipe.rfd comme
      -- fd factice (valeur ignorée dans fork_worker, uniquement pour l'appel
      -- à close() dans le parent — fd déjà ouvert, sans effet néfaste).
      restart_fn: -> fork_worker "AUTH",
        (-> require("auth.worker").run_auth_worker auth_cfg),
        pipe.rfd
    }
  }

  for w in *workers
    w.pid = w.restart_fn!

  status   = ffi.new "int[1]"
  siginfo  = ffi.new "signalfd_siginfo"
  sig_sz   = ffi.sizeof "signalfd_siginfo"

  log_info { action: "supervisor_running", pid: tonumber libc.getpid! }

  while true
    -- Vérifie SIGTERM/SIGHUP via signalfd (non-bloquant — O_NONBLOCK sur le fd)
    rv = libc.read sfd, siginfo, sig_sz
    if rv == sig_sz
      if siginfo.ssi_signo == SIGHUP
        -- Propagation du rechargement à chaud vers Q0 (filtre + ip_whitelist)
        q0 = workers[1]
        if q0 and q0.pid and q0.pid > 0
          log_info { action: "supervisor_sighup", forwarding_to: "Q0", pid: q0.pid }
          libc.kill q0.pid, SIGHUP
      else
        -- SIGTERM : arrêt propre de tous les workers
        log_info { action: "supervisor_sigterm" }
        shutdown_workers workers
        libc._exit 0

    -- waitpid(-1, ..., WNOHANG) : vérifie tous les enfants sans bloquer
    dead_pid = tonumber libc.waitpid -1, status, WNOHANG

    if dead_pid > 0
      for w in *workers
        if w.pid == dead_pid
          exit_code = bit.rshift bit.band(status[0], 0xFF00), 8
          log_warn {
            action:    "worker_died"
            name:      w.name
            pid:       dead_pid
            exit_code: exit_code
          }
          ffi.C.sleep 1
          w.pid = w.restart_fn!
          break

    else
      ffi.C.sleep 1

-- ── main ─────────────────────────────────────────────────────────
log_info { action: "dns-filter_start", version: "1.0.0" }

sfd  = create_signal_fd!
pipe = create_pipe!
log_info { action: "ipc_pipe_created", rfd: pipe.rfd, wfd: pipe.wfd }

supervise pipe, sfd
