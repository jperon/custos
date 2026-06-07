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
config = require "config"

bit = require "bit"

STDOUT_FILENO = 1

ts  = ffi.new "timespec_t"

-- Mappage des niveaux de log vers des valeurs numériques
-- (Plus la valeur est élevée, plus le log est verbeux)
LOG_LEVEL_MAP = {
  EMERG:  8
  ALERT:  7
  CRIT:   6
  ERROR:  5
  WARN:   4
  NOTICE: 3
  INFO:   2
  DEBUG:  1
  ALLOW:  3  -- Par défaut, ALLOW est au niveau NOTICE
  BLOCK:  4  -- Par défaut, BLOCK est au niveau WARN
  TRACE:  6
}

-- Niveau de log configuré, converti en numérique
CURRENT_LOG_LEVEL_NUM = LOG_LEVEL_MAP[config.runtime.log_level] or LOG_LEVEL_MAP.INFO

--- Retourne la valeur numérique d'un niveau de log.
-- @tparam string level Niveau de log (ex: "INFO", "WARN")
-- @treturn number Valeur numérique du niveau, ou 0 si inconnu
get_log_level_num = (level) -> LOG_LEVEL_MAP[level] or 0

--- Indique si un niveau serait effectivement émis (au-dessus du seuil courant).
-- Permet aux call-sites du hot path de sauter la construction du thunk (closure
-- + capture) lorsque le niveau est filtré — write_log filtre déjà, mais APRÈS
-- l'allocation de la closure.
-- @tparam string level Niveau de log (ex: "DEBUG")
-- @treturn boolean true si le niveau est actif
level_enabled = (level) -> get_log_level_num(level) >= CURRENT_LOG_LEVEL_NUM

-- ── Rate-limiting ─────────────────────────────────────────────────
-- Clés discriminantes et fenêtre (secondes) par action ou niveau de log.
-- La clé de RL est fields.action ou, à défaut, le niveau (ALLOW/BLOCK).
RL_CONFIG = {
  captive_probe:      { keys: {"ip", "path"},                window: 60  }
  captive_redirect: { keys: {"ip", "path"},                window: 60  }
  ALLOW:              { keys: {"mac_src", "qname", "qtype"}, window: 30  }
  BLOCK:              { keys: {"mac_src", "qname", "qtype"}, window: 30  }
  no_ipv6_for_client: { keys: {"client"},                    window: 120 }
  no_ipv4_for_client: { keys: {"client"},                    window: 120 }
  neigh_refreshed:    { keys: {},                            window: 30  }
  response_dnsonly:   { keys: {"dst_ip", "qnames"},          window: 30  }
  INFO:               { keys: {"action"},                     window: 10  }
  DEBUG:              { keys: {"action"},                     window: 10  }
}

_rl = {}  -- { fingerprint → { ts, count } }

-- Process-scoped action prefix (set once per worker, inherited by fork children).
_action_prefix = ""

--- Set a prefix prepended to every action= field in log output.
-- Actions already starting with the prefix are not double-prefixed.
-- @tparam string prefix  Short prefix string, e.g. "doh_"
-- @treturn nil
set_action_prefix = (prefix) ->
  _action_prefix = prefix or ""

--- Vérifie si un message doit être supprimé (rate-limiting).
-- @tparam string level  Niveau de log
-- @tparam table  fields Champs du message
-- @treturn number  -1 = supprimer ; 0 = première occurrence ; N>0 = N supprimés depuis dernier log
-- Construit le fingerprint de rate-limiting (action_key + champs discriminants).
-- Concaténation directe (cfg.keys borné, ≤3 clés) plutôt qu'une table
-- intermédiaire + table.concat : ce code s'exécute pour CHAQUE ALLOW/BLOCK, y
-- compris ceux qui seront supprimés, donc on évite l'allocation d'une table par
-- paquet décidé. Fonction pure, exportée pour le test unitaire.
-- @tparam string action_key Clé d'action (fields.action ou niveau)
-- @tparam table  fields     Champs du message
-- @tparam table  keys       Clés discriminantes (cfg.keys)
-- @treturn string Fingerprint
rl_fingerprint = (action_key, fields, keys) ->
  fp = action_key
  for k in *keys
    fp ..= "|" .. tostring fields[k]
  fp

check_rl = (level, fields) ->
  action_key = fields.action or level
  cfg = RL_CONFIG[action_key]
  return 0 unless cfg

  fp = rl_fingerprint action_key, fields, cfg.keys

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

--- Écrit une ligne de log structurée (lazy evaluation obligatoire).
-- Format : [epoch] [pid] LEVEL k1=v1 k2=v2 ...
-- @tparam string level  Niveau de log : "ERROR", "WARN", "INFO", "DEBUG", "TRACE", "ALLOW", "BLOCK"
-- @tparam function thunk Fonction () -> table de champs, appelée uniquement si niveau OK
-- @treturn nil
write_log = (level, thunk) ->
  -- Filtrer selon le niveau de log configuré (vérification rapide avant d'appeler thunk)
  if get_log_level_num(level) < CURRENT_LOG_LEVEL_NUM
    return

  -- Lazy evaluation: appeler thunk pour obtenir les fields
  fields = thunk!
  return unless fields  -- thunk peut retourner nil pour "pas de log"

  -- Apply process-scoped action prefix if set and not already present.
  if _action_prefix != "" and fields.action
    unless fields.action\sub(1, #_action_prefix) == _action_prefix
      new_fields = {}
      for k, v in pairs fields
        new_fields[k] = v
      new_fields.action = _action_prefix .. fields.action
      fields = new_fields

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

--- Raccourcis sémantiques vers write_log avec niveaux prédéfinis (tous lazy).
-- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_allow = (thunk) -> write_log "ALLOW", thunk
--- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_block = (thunk) -> write_log "BLOCK", thunk
--- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_info  = (thunk) -> write_log "INFO",  thunk
--- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_warn  = (thunk) -> write_log "WARN",  thunk
--- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_error = (thunk) -> write_log "ERROR", thunk

--- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_debug = (thunk) -> write_log "DEBUG", thunk

--- @tparam function thunk Fonction () -> table de champs clé=valeur
-- @treturn nil
log_trace = (thunk) -> write_log "TRACE", thunk

{ :write_log, :log_allow, :log_block, :log_info, :log_warn, :log_error, :log_debug, :log_trace, :now, :get_log_level_num, :level_enabled, :rl_fingerprint, :set_action_prefix }
