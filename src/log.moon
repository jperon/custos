-- src/log.moon
-- Logging structuré vers un fichier.
-- Format : [epoch] [pid] LEVEL key=value key=value ...
-- Chaque write() est atomique pour les messages <= PIPE_BUF (4096 octets).
-- Les champs sont en key=value pour faciliter l'ingestion par des outils
-- comme lnav, grok ou un simple awk.

{ :ffi, :libc } = require "ffi_defs"
{ :LOG_PATH } = require "config"

bit = require "bit"

-- ── Ouverture du fichier de log ──────────────────────────────────
O_WRONLY = 1
O_CREAT  = 64
O_APPEND = 1024
S_IRUSR  = 256
S_IWUSR = 128
S_IRGRP = 32
S_IROTH = 4

log_fd = libc.open(
  LOG_PATH,
  bit.bor(O_WRONLY, O_CREAT, O_APPEND),
  bit.bor(S_IRUSR, S_IWUSR, S_IRGRP, S_IROTH)
)
error "Impossible d'ouvrir #{LOG_PATH}" if log_fd < 0

ts  = ffi.new "timespec_t"

-- ── API publique ─────────────────────────────────────────────────

--- Retourne le timestamp Unix courant (secondes).
-- @treturn number epoch courant
now = ->
  libc.clock_gettime 0, ts   -- CLOCK_REALTIME = 0
  tonumber ts.tv_sec

--- Écrit une ligne de log structurée.
-- Format : [epoch] [pid] LEVEL k1=v1 k2=v2 ...
-- @tparam string level  Niveau de log : "INFO", "ALLOW", "BLOCK", "WARN", "ERROR"
-- @tparam table  fields Table de champs clé=valeur à inclure dans la ligne
-- @treturn nil
write_log = (level, fields) ->
  epoch = now!
  pid   = tonumber ffi.C.getpid()

  parts = { "[#{epoch}]", "[#{pid}]", level }
  for k, v in pairs fields
    -- Mise en guillemets si la valeur contient des espaces
    sv = tostring v
    if sv\find " "
      table.insert parts, "#{k}=\"#{sv}\""
    else
      table.insert parts, "#{k}=#{sv}"

  line = table.concat(parts, " ") .. "\n"
  libc.write log_fd, line, #line

--- Raccourcis sémantiques vers write_log.
-- @tparam table fields Table de champs clé=valeur
-- @treturn nil
log_allow = (fields) -> write_log "ALLOW", fields
--- @tparam table fields Table de champs clé=valeur
-- @treturn nil
log_block = (fields) -> write_log "BLOCK", fields
--- @tparam table fields Table de champs clé=valeur
-- @treturn nil
log_info  = (fields) -> write_log "INFO",  fields
--- @tparam table fields Table de champs clé=valeur
-- @treturn nil
log_warn  = (fields) -> write_log "WARN",  fields
--- @tparam table fields Table de champs clé=valeur
-- @treturn nil
log_error = (fields) -> write_log "ERROR", fields

{ :write_log, :log_allow, :log_block, :log_info, :log_warn, :log_error, :now }
