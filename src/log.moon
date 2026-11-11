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
CLOCK_MONOTONIC = 1

ts  = ffi.new "timespec_t"

-- ── Instrumentation optionnelle du coût d'écriture ────────────────
-- Mesure la durée du `libc.write` de chaque ligne (benchmark). Désactivée
-- par défaut : quand elle est off, AUCUN appel d'horloge n'est ajouté au
-- chemin nominal (la seule horloge existante reste celle de l'epoch).
-- L'activation passe par `set_timing` (appelé une fois au démarrage par
-- main.moon, après lecture de la config), jamais par un `require "config"`
-- ici : ce module est requis très tôt, avant que la décision de benchmark
-- ne soit arrêtée, et un `require` en hot-path coûterait ~150 ns/ligne.
_timing_enabled = false
_last_write_us  = 0
_timing_start   = ffi.new "timespec_t"
_timing_end     = ffi.new "timespec_t"

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

--- Active/désactive la mesure de durée des écritures de journal.
-- À appeler une fois au démarrage (main.moon), avant les forks, pour que
-- tous les workers héritent de la valeur par COW.
-- @tparam boolean enabled true pour instrumenter les `write` suivants
-- @treturn nil
set_timing = (enabled) ->
  _timing_enabled = enabled and true or false
  nil

--- Durée du dernier `write` de journal mesuré, en microsecondes.
-- Mesure NON récursive : la valeur est celle du `write` TERMINÉ avant l'appel
-- (une ligne ne peut pas porter sa propre durée). Retourne 0 quand
-- l'instrumentation est désactivée ou qu'aucune écriture n'a encore eu lieu.
-- @treturn number durée en µs (entier)
get_last_write_us = -> _last_write_us

-- Microsecondes monotones depuis boot (horloge réservée à l'instrumentation,
-- appelée uniquement quand `_timing_enabled` est vrai).
monotonic_us = ->
  libc.clock_gettime CLOCK_MONOTONIC, _timing_start
  tonumber(_timing_start.tv_sec) * 1000000 + math.floor(tonumber(_timing_start.tv_nsec) / 1000)

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
  captive_redirect:   { keys: {"ip"},                        window: 60  }
  ALLOW:              { keys: {"mac_src", "qname", "qtype"}, window: 30  }
  BLOCK:              { keys: {"mac_src", "qname", "qtype"}, window: 30  }
  no_ipv6_for_client: { keys: {"client"},                    window: 120 }
  no_ipv4_for_client: { keys: {"client"},                    window: 120 }
  neigh_refreshed:    { keys: {},                            window: 30  }
  response_dnsonly:   { keys: {"dst_ip", "qnames"},          window: 30  }
  INFO:               { keys: {"action"},                     window: 10  }
  DEBUG:              { keys: {"action"},                     window: 10  }
}

_rl = {}  -- { fingerprint → { ts, count, exp } }
_rl_inserts = 0

-- Nombre d'insertions entre deux balayages des entrées expirées de `_rl`.
-- Sans purge, une entrée par (MAC, domaine, type) vu resterait en mémoire
-- pour toute la vie du worker. Coût amorti O(1) par insertion.
RL_PURGE_EVERY = 256

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

-- Supprime les entrées dont la fenêtre est expirée (`exp <= epoch`).
-- @tparam number epoch Timestamp courant en secondes
-- @treturn number Nombre d'entrées supprimées
_purge_rl = (epoch) ->
  expired = {}
  for fp, entry in pairs _rl
    expired[#expired + 1] = fp if epoch >= entry.exp
  for fp in *expired
    _rl[fp] = nil
  _rl_inserts = 0
  #expired

--- Vide `_rl` (tests uniquement).
-- Vide la table en place : la référence exportée reste valide.
_rl_reset = ->
  for k in pairs _rl
    _rl[k] = nil
  _rl_inserts = 0

check_rl = (level, fields, epoch) ->
  action_key = fields.action or level
  cfg = RL_CONFIG[action_key]
  return 0 unless cfg

  fp = rl_fingerprint action_key, fields, cfg.keys

  -- write_log laisse `epoch` nil : `ts` vient d'être rempli par clock_gettime.
  -- Les tests passent une valeur explicite pour simuler le temps.
  epoch or= tonumber ts.tv_sec
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
      entry.exp = epoch + cfg.window
      return old_count
  else
    _rl[fp] = { ts: epoch, count: 0, exp: epoch + cfg.window }
    _rl_inserts += 1
    _purge_rl epoch if _rl_inserts >= RL_PURGE_EVERY
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
  if _timing_enabled
    t0 = monotonic_us!
    libc.write STDOUT_FILENO, line, #line
    libc.clock_gettime CLOCK_MONOTONIC, _timing_end
    t1 = tonumber(_timing_end.tv_sec) * 1000000 + math.floor(tonumber(_timing_end.tv_nsec) / 1000)
    _last_write_us = t1 - t0
  else
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

{ :write_log, :log_allow, :log_block, :log_info, :log_warn, :log_error, :log_debug, :log_trace, :now, :get_log_level_num, :level_enabled, :rl_fingerprint, :set_action_prefix, :RL_CONFIG, :RL_PURGE_EVERY, :check_rl, :_rl, :_rl_reset, :set_timing, :get_last_write_us }
