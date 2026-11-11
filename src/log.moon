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
-- Empreinte par défaut : niveau + action + valeurs des champs d'identité
-- ci-dessous. On n'y met JAMAIS les champs volatils (pid, txid, ports,
-- durées, compteurs, tailles) : deux lignes qui n'en diffèrent que par eux
-- doivent fusionner avec `suppressed=N`, pas se masquer mutuellement.
-- Les champs absents ne participent pas à l'empreinte.
RL_IDENTITY_KEYS = {
  "peer", "peer_ip", "peer_mac"
  "ip", "client", "client_ip", "client_mac", "mac", "mac_src", "src_ip"
  "qname", "qnames", "domain", "qtype", "dst_ip"
  "hostname", "sni", "cert", "key"
  "path", "method", "url", "file"
  "ifname", "name", "queue", "worker", "user", "vlan"
  "resolver_ip", "upstream_ip", "addr"
  "rule", "list", "err", "reason", "cmd"
}

-- Résolution : action complète, puis action sans le préfixe du worker, puis
-- règle par défaut du NIVEAU (même quand `action` est présent). Avant ce
-- correctif, une action non listée n'était jamais limitée : les entrées
-- `INFO:`/`DEBUG:` ne s'appliquaient qu'aux messages sans champ `action`.
--
-- Fenêtres : ERROR/CRIT/ALERT/EMERG 10 s (ne jamais masquer longtemps une
-- erreur), WARN/INFO/NOTICE 60 s, DEBUG/TRACE 30 s (fidélité de diagnostic),
-- ALLOW/BLOCK 30 s (une entrée par triplet MAC/domaine/type).
RL_CONFIG = {
  captive_redirect:   { keys: {"ip"},                        window: 60  }
  ALLOW:              { keys: {"mac_src", "qname", "qtype"}, window: 30  }
  BLOCK:              { keys: {"mac_src", "qname", "qtype"}, window: 30  }
  no_ipv6_for_client: { keys: {"client"},                    window: 120 }
  no_ipv4_for_client: { keys: {"client"},                    window: 120 }
  response_dnsonly:   { keys: {"dst_ip", "qnames"},          window: 30  }
  EMERG:              { keys: RL_IDENTITY_KEYS,              window: 10  }
  ALERT:              { keys: RL_IDENTITY_KEYS,              window: 10  }
  CRIT:               { keys: RL_IDENTITY_KEYS,              window: 10  }
  ERROR:              { keys: RL_IDENTITY_KEYS,              window: 10  }
  WARN:               { keys: RL_IDENTITY_KEYS,              window: 60  }
  NOTICE:             { keys: RL_IDENTITY_KEYS,              window: 60  }
  INFO:               { keys: RL_IDENTITY_KEYS,              window: 60  }
  DEBUG:              { keys: RL_IDENTITY_KEYS,              window: 30  }
  TRACE:              { keys: RL_IDENTITY_KEYS,              window: 30  }
}

-- Actions de cycle de vie jamais limitées : un crash répété (`worker_died`,
-- `child_crashed`) ou un rechargement de config ne doit jamais disparaître
-- derrière une fenêtre de suppression, même s'il se répète. Ces actions sont
-- rares hors boucle de crash, donc les laisser passer ne peut pas noyer les
-- logs. La comparaison se fait aussi après strip du préfixe worker.
RL_NEVER_LIMIT = {
  worker_died:                 true
  child_crashed:               true
  worker_started:              true
  worker_stopping:             true
  worker_start:                true
  supervisor_running:          true
  supervisor_sigterm:          true
  supervisor_sighup_reload:    true
  supervisor_sighup_kill:      true
  supervisor_sighup_refork:    true
  supervisor_sighup_forward_auth: true
  "dns-filter_start":          true
  config_source:               true
  config_external_missing:     true
}

-- Fenêtre maximale (sert à réutiliser un slot dont l'entrée est forcément
-- expirée, quelle que soit sa règle d'origine).
RL_MAX_WINDOW = 0
for _, cfg in pairs RL_CONFIG
  RL_MAX_WINDOW = cfg.window if cfg.window > RL_MAX_WINDOW

-- ── État partagé entre processus ──────────────────────────────────
-- Table de hachage à taille fixe (4096 slots × 3 uint32 = 48 Kio) dans une
-- zone mmap(MAP_SHARED|MAP_ANONYMOUS) créée au chargement du module — donc
-- dans le superviseur avant tout fork — et héritée par tous les workers et
-- leurs enfants. Les enfants AUTH/DoH forkés par connexion partagent ainsi le
-- même état, contrairement à l'ancienne table Lua par processus.
--
-- Slot : { hash, dernier_ts, count }. `dernier_ts == 0` = libre. On stocke le
-- hash 32 bits complet et on sonde linéairement : deux empreintes différentes
-- qui tombent dans le même slot occupent des slots distincts, aucune n'est
-- supprimée à tort. Sans verrou : les accès uint32 alignés ne peuvent pas être
-- déchirés ; une course peut produire une ligne en double ou un compteur
-- légèrement faux, jamais une corruption ni un blocage. Table saturée (plus de
-- RL_PROBE_MAX slots occupés) → on journalise sans supprimer.
RL_SLOTS = 4096
RL_SLOT_WORDS = 3
RL_MMAP_BYTES = RL_SLOTS * RL_SLOT_WORDS * 4
RL_PROBE_MAX = 8
PROT_READ = 1
PROT_WRITE = 2
MAP_SHARED = 0x01
MAP_ANONYMOUS = 0x20

_rl_base = nil
_rl = {}   -- repli uniquement si mmap échoue
_rl_fb_n = 0

pcall ->
  ptr = libc.mmap nil, RL_MMAP_BYTES, bit.bor(PROT_READ, PROT_WRITE), bit.bor(MAP_SHARED, MAP_ANONYMOUS), -1, 0
  if ptr != nil and ptr != ffi.cast("void*", -1)
    _rl_base = ffi.cast "uint32_t*", ptr

-- Process-scoped action prefix (set once per worker, inherited by fork children).
_action_prefix = ""

--- Set a prefix prepended to every action= field in log output.
-- Actions already starting with the prefix are not double-prefixed.
-- @tparam string prefix  Short prefix string, e.g. "doh_"
-- @treturn nil
set_action_prefix = (prefix) ->
  _action_prefix = prefix or ""

--- Indique si une action de cycle de vie est exemptée de rate-limiting.
-- Teste l'action telle quelle puis sans le préfixe du worker courant.
-- @tparam string|nil action Champ `action` du message
-- @treturn boolean true si l'action ne doit jamais être supprimée
_rl_never_limited = (action) ->
  return false unless action
  return true if RL_NEVER_LIMIT[action]
  if _action_prefix != "" and action\sub(1, #_action_prefix) == _action_prefix
    return true if RL_NEVER_LIMIT[action\sub(#_action_prefix + 1)]
  false

--- Résout la configuration de rate-limiting d'un message.
-- Ordre : action complète, action sans le préfixe du worker, puis défaut du
-- niveau (qui s'applique même avec un champ `action`).
-- @tparam string level  Niveau de log
-- @tparam table  fields Champs du message
-- @treturn table|nil Configuration `{keys, window}` ou nil si aucune règle
_rl_resolve_cfg = (level, fields) ->
  action = fields.action
  if action
    cfg = RL_CONFIG[action]
    return cfg if cfg
    if _action_prefix != "" and action\sub(1, #_action_prefix) == _action_prefix
      cfg = RL_CONFIG[action\sub(#_action_prefix + 1)]
      return cfg if cfg
  RL_CONFIG[level]

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

-- Séparateurs précalculés pour le hash (évite une allocation de string par
-- champ et par message sur le chemin chaud ALLOW/BLOCK).
RL_SEP = {}
for k in *RL_IDENTITY_KEYS
  RL_SEP[k] = "\1" .. k .. "="

--- Hash 32 bits djb2 incrémental, sans allocation de table.
-- @tparam number h      Hash courant
-- @tparam string s      Chaîne à incorporer
-- @treturn number Hash mis à jour (32 bits signé)
_rl_hash_step = (h, s) ->
  for i = 1, #s
    h = bit.tobit(h * 33 + s\byte(i))
  h

--- Hash de l'empreinte d'un message (niveau + action + champs discriminants).
-- Les champs absents ne participent pas. Fonction pure, exportée pour les
-- tests (collision de slot).
-- @tparam string level  Niveau de log
-- @tparam table  fields Champs du message
-- @tparam table|nil keys Clés discriminantes (cfg.keys ; résolues si nil)
-- @treturn number Hash 32 bits non signé
_rl_hash = (level, fields, keys) ->
  action = fields.action or level
  unless keys
    cfg = _rl_resolve_cfg level, fields
    keys = cfg and cfg.keys or {}
  h = _rl_hash_step 0, level
  h = _rl_hash_step h, "\1"
  h = _rl_hash_step h, action
  for k in *keys
    v = fields[k]
    if v != nil
      h = _rl_hash_step h, (RL_SEP[k] or ("\1" .. k .. "="))
      h = _rl_hash_step h, tostring v
  h % 4294967296

--- Vide l'état partagé (tests uniquement).
_rl_reset = ->
  if _rl_base
    for i = 0, RL_SLOTS * RL_SLOT_WORDS - 1
      _rl_base[i] = 0
  else
    for k in pairs _rl
      _rl[k] = nil
    _rl_fb_n = 0

check_rl = (level, fields, epoch) ->
  action_key = fields.action or level
  return 0 if _rl_never_limited fields.action
  cfg = _rl_resolve_cfg level, fields
  return 0 unless cfg

  -- write_log laisse `epoch` nil : `ts` vient d'être rempli par clock_gettime.
  -- Les tests passent une valeur explicite pour simuler le temps.
  epoch or= tonumber ts.tv_sec

  if _rl_base
    -- Le niveau et l'action complète font partie de l'empreinte : une même
    -- action émise en INFO et en WARN ne partage pas le compteur de l'autre.
    h = _rl_hash level, fields, cfg.keys
    base = _rl_base
    window = cfg.window
    slot = h % RL_SLOTS
    for _probe = 1, RL_PROBE_MAX
      off = slot * RL_SLOT_WORDS
      sh = tonumber base[off]
      sts = tonumber base[off + 1]
      if sts == 0
        base[off] = h
        base[off + 1] = epoch
        base[off + 2] = 0
        return 0
      if sh == h
        if epoch - sts < window
          base[off + 2] = tonumber(base[off + 2]) + 1
          return -1   -- supprimer
        -- Fenêtre expirée : retourner le compteur puis réinitialiser
        old_count = tonumber base[off + 2]
        base[off + 1] = epoch
        base[off + 2] = 0
        return old_count
      -- Entrée forcément expirée (toutes fenêtres ≤ RL_MAX_WINDOW) : recyclage.
      if epoch - sts >= RL_MAX_WINDOW
        base[off] = h
        base[off + 1] = epoch
        base[off + 2] = 0
        return 0
      slot = (slot + 1) % RL_SLOTS
    return 0   -- table saturée : journaliser sans supprimer
  else
    -- Repli par processus si mmap a échoué. Plafond global : on repart de zéro
    -- plutôt que de laisser la table croître indéfiniment.
    fp = rl_fingerprint "#{level}|#{action_key}", fields, cfg.keys
    entry = _rl[fp]
    if entry
      if epoch - entry.ts < cfg.window
        entry.count += 1
        return -1
      old_count = entry.count
      entry.ts = epoch
      entry.count = 0
      return old_count
    else
      if _rl_fb_n >= RL_SLOTS
        for k in pairs _rl
          _rl[k] = nil
        _rl_fb_n = 0
      _rl[fp] = { ts: epoch, count: 0 }
      _rl_fb_n += 1
      return 0

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

{ :write_log, :log_allow, :log_block, :log_info, :log_warn, :log_error, :log_debug, :log_trace, :now, :get_log_level_num, :level_enabled, :rl_fingerprint, :set_action_prefix, :RL_CONFIG, :RL_SLOTS, :check_rl, :_rl_hash, :_rl_reset }
