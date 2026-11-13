-- src/lib/sighup.moon
-- Veille d'un signal POSIX sans handler asynchrone.
--
-- Le signal est bloqué (sigprocmask) puis lu via signalfd non bloquant : c'est
-- le mécanisme déjà utilisé par le superviseur (src/main.moon:95-112) et par le
-- worker d'événements (src/worker_events.moon:59-73). L'appelant interroge
-- `pending` depuis sa boucle normale.
--
-- Pourquoi jamais ffi.C.signal + callback Lua : LuaJIT refuse d'entrer dans un
-- callback FFI quand du code JIT est en cours (`jit_base` non nul) ; il écrit
-- alors « bad callback » (lj_ccallback.c:726-730) et appelle exit(). Un
-- gestionnaire de signal doit donc seulement laisser une trace côté noyau,
-- ce que fait signalfd.

ffi = require "ffi"
bit = require "bit"
{ :libc } = require "ffi_defs"
{ :SIG_BLOCK, :O_NONBLOCK } = require "lib.os_constants"

-- Déclarations minimales, tolérées en double (ffi_defs ou un helper de test
-- les a peut-être déjà posées) : même procédé que src/lib/os_constants.moon:19.
for _, c in ipairs {
  "typedef struct { uint8_t _opaque[128]; } sigset_t_custos;"
  [[int sigprocmask(int how, const sigset_t_custos *set,
                    sigset_t_custos *oldset);
    int signalfd(int fd, const sigset_t_custos *mask, int flags);
    long read(int fd, void *buf, unsigned long n);
    int close(int fd);]]
  "typedef struct { uint32_t ssi_signo; uint8_t _pad[124]; } signalfd_siginfo;"
}
  pcall ffi.cdef, c

SIGHUP = 1

--- Construit un masque de signaux ne contenant que `signo`.
-- @tparam number signo Numéro de signal POSIX
-- @treturn cdata sigset_t_custos renseigné
make_mask = (signo) ->
  mask = ffi.new "sigset_t_custos"
  ffi.fill mask, ffi.sizeof(mask), 0
  word = ffi.cast "uint32_t*", mask
  word[0] = bit.lshift 1, signo - 1
  mask

-- Méthodes du veilleur (état porté par l'instance, créée par create_watcher).
watcher_mt = {
  __index: {
    --- Vide la file du signalfd.
    -- @treturn boolean true si au moins une occurrence de `signo` y était
    pending: (self) ->
      seen = false
      while true
        n = tonumber libc.read self.fd, self._siginfo, self._size
        break if n != self._size
        seen = true if tonumber(self._siginfo.ssi_signo) == self.signo
      seen

    --- Ferme le fd du veilleur. Le signal reste bloqué pour le processus
    -- (comportement voulu : le veilleur vit aussi longtemps que le worker).
    -- @treturn nil
    close: (self) ->
      libc.close self.fd
      nil
  }
}

--- Crée un veilleur pour `signo` (SIGHUP par défaut).
-- Le signal est bloqué dans le processus courant AVANT l'ouverture du fd :
-- plus aucun handler C asynchrone n'est nécessaire.
-- @tparam[opt=1] number signo Numéro de signal POSIX
-- @treturn table veilleur (`:pending()`, `:close()`, champ `fd`)
-- @raise string si sigprocmask ou signalfd échoue
create_watcher = (signo=SIGHUP) ->
  mask = make_mask signo
  if libc.sigprocmask(SIG_BLOCK, mask, nil) != 0
    error "sigprocmask() échoué pour le signal #{signo}"

  fd = libc.signalfd -1, mask, O_NONBLOCK
  error "signalfd() échoué pour le signal #{signo}" if fd < 0

  setmetatable {
    fd: fd
    signo: signo
    _siginfo: ffi.new "signalfd_siginfo"
    _size: ffi.sizeof "signalfd_siginfo"
  }, watcher_mt

{ :SIGHUP, :create_watcher, :make_mask }
