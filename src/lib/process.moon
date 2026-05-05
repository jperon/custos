-- src/lib/process.moon
-- Helpers de gestion de processus enfants via libc/FFI.
--
-- Ce module centralise le fork utilisé par le superviseur principal et par les
-- sous-services qui doivent créer des enfants sans dépendre de LuaSocket.fork()
-- ni de luaposix.

{ :ffi, :libc } = require "ffi_defs"
{ :log_info, :log_warn, :log_error } = require "log"

bit = require "bit"

SIG_UNBLOCK = 1
SIGTERM     = 15
SIGHUP      = 1
WNOHANG     = 1

--- Débloque SIGTERM/SIGHUP dans un processus enfant.
-- Le superviseur parent masque ces signaux pour signalfd ; après fork(), les
-- enfants héritent de ce masque et doivent donc le lever explicitement.
-- @treturn nil
unblock_worker_signals = ->
  unmask = ffi.new "sigset_t_custos"
  ffi.fill unmask, ffi.sizeof(unmask), 0

  word = ffi.cast "uint32_t*", unmask
  word[0] = bit.bor bit.lshift(1, SIGTERM - 1), bit.lshift(1, SIGHUP - 1)

  libc.sigprocmask SIG_UNBLOCK, unmask, nil
  nil

--- Renomme le processus courant (visible dans ps et syslog).
-- Utilise PR_SET_NAME (option 15) ; le nom est tronqué à 15 caractères par le kernel.
-- @tparam string name Nouveau nom du processus
-- @treturn nil
set_process_name = (name) ->
  libc.prctl 15, ffi.cast("unsigned long", ffi.cast("const char*", name)), 0, 0, 0
  nil

--- Arme PR_SET_PDEATHSIG pour tuer l'enfant si son parent disparaît.
-- @tparam string name Nom logique de l'enfant, utilisé dans les logs
-- @treturn boolean true si prctl a réussi
set_parent_death_signal = (name) ->
  if libc.prctl(1, SIGTERM, 0, 0, 0) != 0
    errno = tonumber(ffi.C.__errno_location()[0])
    log_error { action: "prctl_failed", name: name, errno: errno }
    return false
  true

--- Fork et lance une fonction dans le processus enfant.
-- Dans l'enfant, cette fonction ne retourne jamais : elle appelle _exit().
-- @tparam string name Nom logique du processus enfant
-- @tparam function child_fn Fonction exécutée dans l'enfant
-- @tparam any arg Argument optionnel transmis à child_fn
-- @tparam table|nil [opts] Options :
--   - unblock_signals: boolean, défaut true
--   - parent_death_signal: boolean, défaut true
--   - log_start: boolean, défaut true
-- @treturn number PID de l'enfant dans le parent
-- @raise string si fork échoue
fork_child = (name, child_fn, arg=nil, opts=nil) ->
  opts or= {}

  unblock_signals = opts.unblock_signals
  unblock_signals = true if unblock_signals == nil

  parent_death_signal = opts.parent_death_signal
  parent_death_signal = true if parent_death_signal == nil

  log_start = opts.log_start
  log_start = true if log_start == nil

  parent_pid = tonumber libc.getpid!
  pid = libc.fork!

  if pid < 0
    error "fork() échoué pour #{name}"

  if pid == 0
    set_process_name "custos:#{name}"

    if unblock_signals
      unblock_worker_signals!

    if parent_death_signal
      unless set_parent_death_signal name
        libc._exit 1

      -- Si le parent est mort entre fork() et prctl(), sortir immédiatement.
      if tonumber(libc.getppid!) != parent_pid
        libc._exit 0

    ok, err = pcall child_fn, arg
    unless ok
      log_error { action: "child_crashed", name: name, pid: tonumber(libc.getpid!), err: tostring err }
      libc._exit 1

    libc._exit 0

  if log_start
    log_info { action: "worker_started", name: name, pid: tonumber pid }

  pid

--- Compatibilité superviseur : fork un worker avec un argument.
-- @tparam string name Nom du worker
-- @tparam function worker_fn Fonction exécutée dans l'enfant
-- @tparam any worker_arg Argument transmis à worker_fn
-- @treturn number PID du worker dans le parent
fork_worker = (name, worker_fn, worker_arg=nil) ->
  fork_child name, worker_fn, worker_arg

--- Envoie un signal à un enfant si son PID est valide.
-- @tparam number pid PID cible
-- @tparam number sig Signal POSIX
-- @treturn boolean true si kill() a réussi
kill_child = (pid, sig=SIGTERM) ->
  return false unless pid and pid > 0
  libc.kill(pid, sig) == 0

--- Envoie SIGTERM à tous les workers d'une table {name, pid, ...}.
-- @tparam table workers Table de workers
-- @treturn nil
terminate_workers = (workers) ->
  for w in *workers
    if w.pid and w.pid > 0
      log_info { action: "worker_stopping", name: w.name, pid: w.pid }
      libc.kill w.pid, SIGTERM
  nil

--- Attend tous les enfants restants.
-- @treturn nil
wait_all_children = ->
  status = ffi.new "int[1]"
  dead = libc.waitpid -1, status, 0
  while dead > 0
    dead = libc.waitpid -1, status, 0
  nil

--- Termine tous les workers puis attend la sortie de tous les enfants.
-- @tparam table workers Table de workers
-- @treturn nil
shutdown_workers = (workers) ->
  terminate_workers workers
  wait_all_children!

--- Récupère un enfant terminé sans bloquer.
-- @treturn number PID terminé, ou 0 si aucun, ou -1 si erreur/aucun enfant
-- @treturn number Code de sortie calculé à partir du status waitpid
reap_one = ->
  status = ffi.new "int[1]"
  dead_pid = tonumber libc.waitpid -1, status, WNOHANG
  exit_code = 0
  if dead_pid and dead_pid > 0
    exit_code = bit.rshift bit.band(status[0], 0xFF00), 8
  dead_pid, exit_code

{
  :SIGTERM, :SIGHUP, :WNOHANG
  :set_process_name
  :unblock_worker_signals
  :set_parent_death_signal
  :fork_child
  :fork_worker
  :kill_child
  :terminate_workers
  :wait_all_children
  :shutdown_workers
  :reap_one
}
