-- src/log.moon
-- Logging structuré vers stdout.
-- Format : [epoch] [pid] LEVEL key=value key=value ...
-- Chaque write() est atomique pour les messages <= PIPE_BUF (4096 octets)
-- sur un pipe : compatible procd (logread) et systemd-journald.
-- Les champs sont en key=value pour faciliter l'ingestion par des outils
-- comme lnav, grok ou un simple awk.
--
-- Rate-limiting intégré : les messages répétitifs (même action + champs
-- discriminants) sont supprimés pendant une fenêtre configurable. Le premier
-- message après la fenêtre inclut le champ `suppressed=N`.

{ :ffi, :libc } = require "ffi_defs"
{ :LOG_LEVEL } = require "config" -- Importer LOG_LEVEL de config.moon

bit = require "bit"

STDOUT_FILENO = 1

ts  = ffi.new "timespec_t"

-- Mappage des niveaux de log vers des valeurs numériques
-- (Plus la valeur est élevée, plus le log est verbeux)
LOG_LEVEL_MAP = {
  ERROR: 5,
  WARN:  4,
  INFO:  3,
  DEBUG: 2,
  TRACE: 1,
  ALLOW: 3, -- Par défaut, ALLOW est au niveau INFO
  BLOCK: 3  -- Par défaut, BLOCK est au niveau INFO
}

-- Niveau de log configuré, converti en numérique
CURRENT_LOG_LEVEL_NUM = LOG_LEVEL_MAP[LOG_LEVEL] or LOG_LEVEL_MAP.INFO

--- Retourne la valeur numérique d'un niveau de log.
-- @tparam string level Niveau de log (ex: "INFO", "WARN")
-- @treturn number Valeur numérique du niveau, ou 0 si inconnu
get_log_level_num = (level) -> LOG_LEVEL_MAP[level] or 0

-- ── Rate-limiting ─────────────────────────────────────────────────
-- Clés discriminantes et fenêtre (secondes) par action ou niveau de log.
-- La clé de RL est fields.action ou, à défaut, le niveau (ALLOW/BLOCK).
RL_CONFIG = {
  captive_probe:      { keys: {"ip", "path"},                window: 60  }
  captive_redirect_q2:   { keys: {"ip", "path"},                window: 60  }
  ALLOW:              { keys: {"mac_src", "qname", "qtype"}, window: 30  }
  no_ipv6_for_client: { keys: {"client"},                    window: 120 }
  no_ipv4_for_client: { keys: {"client"},                    window: 120 }
  neigh_refreshed:    { keys: {},                            window: 30  }
  response_dnsonly:   { keys: {"dst_ip", "qnames"},          window: 30  }
}

_rl = {}  -- { fingerprint → { ts, count } }

--- Vérifie si un message doit être supprimé (rate-limiting).
-- @tparam string level  Niveau de log
-- @tparam table  fields Champs du message
-- @treturn number  -1 = supprimer ; 0 = première occurrence ; N>0 = N supprimés depuis dernier log
check_rl = (level, fields) ->
  action_key = fields.action or level
  cfg = RL_CONFIG[action_key]
  return 0 unless cfg

  -- Construire le fingerprint à partir des champs discriminants
  parts = { action_key }
  for k in *cfg.keys
    parts[#parts + 1] = tostring fields[k] or ""
  fp = table.concat parts, "|"

  epoch = tonumber ts.tv_sec   -- réutilise le timespec déjà rempli dans write_log
  entry = _rl[fp]
  if entry
    if epoch - entry.ts < cfg.window
      entry.count += 1
      return -1   -- supprimer
    else
      -- Fenêtre expirée : retourner le compteur puis réinitialiser
      old_count  = entry.count
      entry.ts   = epoch
      entry.count = 0
      return old_count
  else
    _rl[fp] = { ts: epoch, count: 0 }
    return 0   -- première occurrence

-- ── Formatage ─────────────────────────────────────────────────────

--- Retourne le timestamp Unix courant (secondes).
-- @treturn number epoch courant
now = ->
  libc.clock_gettime 0, ts   -- CLOCK_REALTIME = 0
  tonumber ts.tv_sec

--- Écrit une ligne de log structurée.
-- Format : [epoch] [pid] LEVEL k1=v1 k2=v2 ...
-- @tparam string level  Niveau de log : "ERROR", "WARN", "INFO", "DEBUG", "TRACE", "ALLOW", "BLOCK"
-- @tparam table  fields Table de champs clé=valeur à inclure dans la ligne
-- @treturn nil
write_log = (level, fields) ->
  -- Filtrer selon le niveau de log configuré
  if get_log_level_num(level) < CURRENT_LOG_LEVEL_NUM
    return

  libc.clock_gettime 0, ts   -- remplit ts utilisé par check_rl
  epoch = tonumber ts.tv_sec
  pid   = tonumber ffi.C.getpid()

  suppressed = check_rl level, fields
  return if suppressed == -1

  parts = { "[#{epoch}]", "[#{pid}]", level }
  for k, v in pairs fields
    -- Mise en guillemets si la valeur contient des espaces
    sv = tostring v
    if sv\find " "
      table.insert parts, "#{k}=\"#{sv}\""
    else
      table.insert parts, "#{k}=#{sv}"
  table.insert parts, "suppressed=#{suppressed}" if suppressed > 0

  line = table.concat(parts, " ") .. "\n"
  libc.write STDOUT_FILENO, line, #line

--- Raccourcis sémantiques vers write_log avec niveaux prédéfinis.
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

--- @tparam table fields Table de champs clé=valeur
-- @treturn nil
log_debug = (fields) -> write_log "DEBUG", fields

--- @tparam table fields Table de champs clé=valeur
-- @treturn nil
log_trace = (fields) -> write_log "TRACE", fields

{ :write_log, :log_allow, :log_block, :log_info, :log_warn, :log_error, :log_debug, :log_trace, :now, :get_log_level_num }
