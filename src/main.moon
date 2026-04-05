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

{ :ffi, :libc } = require "ffi_defs"
{ :log_info, :log_warn, :log_error } = require "log"

-- ── Helpers POSIX ────────────────────────────────────────────────
ffi.cdef [[
  unsigned int sleep(unsigned int seconds);
  int getpid(void);
]]

WNOHANG  = 1   -- waitpid non-bloquant

-- ── Création du pipe IPC ─────────────────────────────────────────
create_pipe = ->
  fds = ffi.new "int[2]"
  -- pipe2 avec O_NONBLOCK (2048) sur le fd de lecture pour que drain_pipe()
  -- dans Q1 soit non-bloquant. Plus fiable que pipe+fcntl avec LuaJIT FFI.
  rc  = libc.pipe2 fds, 2048
  error "pipe2() échoué" if rc != 0

  { rfd: fds[0], wfd: fds[1] }

-- ── Fork d'un worker ─────────────────────────────────────────────
-- worker_fn : function() → appelée dans le processus enfant
-- Retourne le pid de l'enfant (dans le parent), ou ne retourne pas (enfant).
fork_worker = (name, worker_fn, pipe_fd) ->
  pid = libc.fork!

  if pid < 0
    error "fork() échoué pour #{name}"

  if pid == 0
    -- ── Processus enfant ───────────────────────────────────────
    -- Ferme les fd non nécessaires hérités du parent
    -- (l'autre extremité du pipe est fermée dans chaque worker)
    worker_fn pipe_fd
    libc._exit 0
    -- _exit() ne retourne jamais

  -- ── Processus parent ───────────────────────────────────────────
  log_info { action: "worker_started", name: name, pid: tonumber pid }
  pid

-- ── Boucle de supervision ────────────────────────────────────────
supervise = (pipe) ->
  -- Table des workers : { name, pid, restart_fn }
  -- restart_fn : closure qui reforke le worker avec les bons fds

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
  }

  -- Démarrage initial des workers
  for w in *workers
    w.pid = w.restart_fn!

  status = ffi.new "int[1]"

  log_info { action: "supervisor_running", pid: tonumber libc.getpid! }

  while true
    -- waitpid(-1, ..., WNOHANG) : vérifie tous les enfants sans bloquer
    dead_pid = tonumber libc.waitpid -1, status, WNOHANG

    if dead_pid > 0
      -- Un enfant est mort — on identifie lequel et on le relance
      for w in *workers
        if w.pid == dead_pid
          exit_code = bit.rshift bit.band(status[0], 0xFF00), 8
          log_warn {
            action:    "worker_died"
            name:      w.name
            pid:       dead_pid
            exit_code: exit_code
          }
          -- Délai avant relance pour éviter une boucle de crash rapide
          ffi.C.sleep 1
          w.pid = w.restart_fn!
          break

    else
      -- Pas d'enfant mort : petite pause pour ne pas spinning
      ffi.C.sleep 1

-- ── main ─────────────────────────────────────────────────────────
log_info { action: "dns-filter_start", version: "1.0.0" }

pipe = create_pipe!
log_info { action: "ipc_pipe_created", rfd: pipe.rfd, wfd: pipe.wfd }

supervise pipe
