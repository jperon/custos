-- src/lib/pipe_batch.moon
-- Tampon d'écriture groupée sur un pipe (producteurs de messages courts).
--
-- Motivation : chaque question DNS écrivait une ligne TSV dans le pipe
-- `events` et un message binaire de 22 octets dans le pipe `learn` — deux
-- `write()` par paquet, donc deux syscalls sur le chemin chaud du worker
-- questions (cf. docs/agents/perf.md §16.5 piste 7 et §20). Ce module accumule
-- les messages et les vide en UN `write()` par tranche ≤ PIPE_BUF_ATOMIC
-- (4096 o) : les écritures d'un même producteur ne coûtent plus qu'un appel
-- système par lot, et restent atomiques vis-à-vis des autres producteurs du
-- même pipe (plusieurs workers écrivent dans les pipes events/learn).
--
-- Deux formes, selon le protocole du pipe :
--   * `new_records` : messages de taille FIXE (pipe learn : ip16 + mac6 =
--     22 octets, cf. mac_learner) ;
--   * `new_lines` : messages terminés par \n (pipe events : lignes TSV).
-- Dans les deux cas l'ordre d'insertion est préservé et un message n'est
-- jamais coupé entre deux `write()`.
--
-- Le vidage est à la charge de l'appelant : en fin de lot NFQUEUE
-- (`on_batch_end`), sur `on_idle`, et avant toute attente longue. Les messages
-- encore tamponnés au moment d'un arrêt brutal du processus sont perdus (comme
-- avant sur EAGAIN) : le tampon est vidé à chaque fin de lot, la fenêtre de
-- perte est donc bornée à un lot.

{ :ffi, :libc } = require "ffi_defs"
{ :log_warn } = require "log"

-- Borne d'une écriture atomique sur un pipe Linux (PIPE_BUF) : au-delà, le
-- noyau peut couper l'écriture et entrelacer les octets de deux producteurs.
PIPE_BUF_ATOMIC = 4096

--- Écrit un tampon en un seul `write()` et journalise un échec.
-- Un pipe non bloquant plein rend EAGAIN : le message est abandonné (comme
-- avant), mais le journal porte le nombre d'octets perdus.
-- @tparam number fd    Descripteur d'écriture
-- @tparam any    buf   Chaîne Lua ou tampon FFI
-- @tparam number len   Nombre d'octets à écrire (≤ PIPE_BUF_ATOMIC)
-- @treturn boolean true si tout a été écrit
write_buf = (fd, buf, len) ->
  n = libc.write fd, buf, len
  return true if n == len
  errno_p = libc.__errno_location!
  errno = if errno_p then tonumber(errno_p[0]) else 0
  log_warn -> {
    action:  "pipe_batch_write_failed"
    fd:      fd
    bytes:   len
    written: tonumber(n) or -1
    errno:   errno
  }
  false

--- Tampon de messages de taille fixe (pipe binaire, ex. learn 22 octets).
-- La capacité est arrondie vers le bas à un multiple de `rec_size` : une
-- tranche contient toujours des messages entiers, jamais un préfixe.
-- @tparam number|nil fd        Descripteur d'écriture (nil = tampon inerte)
-- @tparam number     rec_size  Taille d'un message en octets (> 0)
-- @tparam[opt] number capacity Capacité de la tranche (défaut PIPE_BUF_ATOMIC)
-- @treturn table|nil Tampon { add, flush, pending, bytes, fd }
new_records = (fd, rec_size, capacity=PIPE_BUF_ATOMIC) ->
  return nil unless rec_size and rec_size > 0
  cap = math.floor(capacity / rec_size) * rec_size
  return nil if cap < rec_size
  buf    = ffi.new "uint8_t[?]", cap
  nbytes = 0
  ncount = 0

  flush = ->
    return true if ncount == 0
    ok = write_buf fd, buf, nbytes
    nbytes = 0
    ncount = 0
    ok

  --- Ajoute un message ; refusé s'il n'a pas exactement `rec_size` octets.
  -- Une tranche pleine est vidée avant l'ajout.
  -- @tparam string msg Message complet
  -- @treturn boolean true si le message a été pris dans le tampon
  add = (msg) ->
    return false unless fd
    unless type(msg) == "string"
      log_warn -> { action: "pipe_batch_record_size_invalid", bytes: -1, max: rec_size }
      return false
    unless #msg == rec_size
      log_warn -> { action: "pipe_batch_record_size_invalid", bytes: #msg, max: rec_size }
      return false
    if nbytes + rec_size > cap
      return false unless flush!
    ffi.copy buf + nbytes, msg, rec_size
    nbytes += rec_size
    ncount += 1
    true

  { :fd, :add, :flush
    pending: -> ncount
    bytes:   -> nbytes }

--- Tampon de lignes (messages terminés par \n, ex. pipe events TSV).
-- Les lignes sont accumulées telles quelles puis concaténées au vidage : une
-- tranche ≤ capacité est écrite en un seul `write()`.
-- @tparam number|nil fd         Descripteur d'écriture (nil = tampon inerte)
-- @tparam[opt] number capacity  Capacité de la tranche (défaut PIPE_BUF_ATOMIC)
-- @treturn table Tampon { add, flush, pending, bytes, fd }
new_lines = (fd, capacity=PIPE_BUF_ATOMIC) ->
  parts  = {}
  nbytes = 0

  flush = ->
    return true if #parts == 0
    data = table.concat parts
    ok = write_buf fd, data, #data
    parts  = {}
    nbytes = 0
    ok

  --- Ajoute une ligne (terminée par \n) ; refusée si elle dépasse la capacité.
  -- Une tranche pleine est vidée avant l'ajout.
  -- @tparam string line Ligne complète
  -- @treturn boolean true si la ligne a été prise dans le tampon
  add = (line) ->
    return false unless fd
    return false unless type(line) == "string" and #line > 0
    if #line > capacity
      log_warn -> { action: "pipe_batch_line_too_long", bytes: #line, max: capacity }
      return false
    if nbytes + #line > capacity
      return false unless flush!
    parts[#parts + 1] = line
    nbytes += #line
    true

  { :fd, :add, :flush
    pending: -> #parts
    bytes:   -> nbytes }

{ :new_records, :new_lines, :write_buf, :PIPE_BUF_ATOMIC }
