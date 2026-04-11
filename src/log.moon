-- src/log.moon
-- Logging structuré vers stdout.
-- Format : [epoch] [pid] LEVEL key=value key=value ...
-- Chaque write() est atomique pour les messages <= PIPE_BUF (4096 octets)
-- sur un pipe : compatible procd (logread), systemd-journald et docker logs.
-- Les champs sont en key=value pour faciliter l'ingestion par des outils
-- comme lnav, grok ou un simple awk.

{ :ffi, :libc } = require "ffi_defs"

bit = require "bit"

STDOUT_FILENO = 1

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
  libc.write STDOUT_FILENO, line, #line

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
