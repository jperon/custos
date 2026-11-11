-- src/metrics.moon
-- Compteurs de verdicts par règle et export JSON périodique.
--
-- Les compteurs vivent dans la mémoire du worker (un worker_questions par
-- file NFQUEUE). Chaque worker enregistre son propre instantané dans
-- <répertoire d'exécution>/metrics-<nom>.json, écrit atomiquement (fichier
-- temporaire + os.rename) ; la page admin /admin/metrics agrège les fichiers
-- de tous les workers. Un fichier absent, corrompu ou périmé y est ignoré.
--
-- Chemin par paquet : `maybe_flush` ne fait qu'un incrément et une
-- comparaison ; l'horloge n'est consultée qu'une fois tous les `check_every`
-- paquets (1024 par défaut, soit au plus ~1 fois/s à 1 kpps), jamais par
-- paquet. `metrics.enabled = false` : l'appelant n'appelle pas `maybe_flush`
-- et `record_verdict` retourne immédiatement — aucun coût dans le hot-path.

config = require "config"
json   = require "lib.json"

metrics_cfg = config.metrics or {}

_metrics = {}
_rule_order = {}
-- `enabled` n'est désactivé que s'il vaut explicitement `false` (comme init).
_enabled = metrics_cfg.enabled != false
_max_rules = metrics_cfg.max_rules or 1000
_flush_interval = metrics_cfg.flush_interval or 60

-- État de l'export périodique, renseigné par init() depuis le worker.
_dir = nil
_name = nil
_clock = os.time
_check_every = 1024
_pkt_count = 0
_last_flush = 0
_tmp_seq = 0

--- Ensure a rule entry exists in the metrics table.
_ensure_rule_entry = (rule_id) ->
  return if _metrics[rule_id]

  -- Check if we need to evict (LRU)
  if #_rule_order >= _max_rules
    lru_rule = table.remove _rule_order, 1
    _metrics[lru_rule] = nil

  _metrics[rule_id] = {
    allow_count:   0
    refuse_count:  0
    dnsonly_count: 0
  }

  table.insert _rule_order, rule_id

--- Initialise le module (compteurs et export périodique).
-- @tparam ?table cfg  Section `metrics` de la config (`enabled`, `max_rules`,
--                     `flush_interval`)
-- @tparam ?table opts Options d'export : `dir` (répertoire d'exécution),
--                     `name` (nom du worker), `clock` (horloge injectable),
--                     `check_every` (paquets entre deux lectures d'horloge)
init = (cfg, opts) ->
  cfg or= {}
  opts or= {}
  _enabled = cfg.enabled != false
  _max_rules = cfg.max_rules or 1000
  _flush_interval = cfg.flush_interval or 60
  _dir = opts.dir
  _name = opts.name
  _clock = opts.clock or os.time
  _check_every = opts.check_every or 1024
  _pkt_count = 0
  _last_flush = 0

--- Record a verdict for a rule.
-- @tparam string rule_id Identifiant de règle
-- @tparam string verdict "allow", "refuse" ou "dnsonly"
record_verdict = (rule_id, verdict) ->
  return unless _enabled
  return unless rule_id and verdict

  _ensure_rule_entry rule_id

  if verdict == "allow"
    _metrics[rule_id].allow_count += 1
  elseif verdict == "refuse"
    _metrics[rule_id].refuse_count += 1
  elseif verdict == "dnsonly"
    _metrics[rule_id].dnsonly_count += 1

--- Get metrics as JSON-exportable table.
-- @treturn table { timestamp, rules = { {rule_id, verdicts = {allow, refuse,
--                 dnsonly}}, … } }
get_metrics_json = ->
  rules = {}
  if _enabled
    for rule_id in *_rule_order
      metric = _metrics[rule_id]
      continue unless metric

      rules[#rules + 1] = {
        rule_id:  rule_id
        verdicts: {
          allow:   metric.allow_count
          refuse:  metric.refuse_count
          dnsonly: metric.dnsonly_count
        }
      }

  {
    timestamp: _clock!
    rules: rules
  }

--- Chemin du fichier d'instantané de ce worker, ou nil si non configuré.
-- @treturn string|nil
file_path = ->
  return nil unless _dir and _name
  "#{_dir}/metrics-#{_name}.json"

--- Écrit un instantané de façon atomique (temporaire + os.rename).
-- Le fichier final n'est jamais partiellement visible : le temporaire porte
-- un suffixe `.tmp.<n>` qui ne correspond pas au motif `metrics-*.json`.
-- @tparam table snapshot Instantané retourné par get_metrics_json
-- @treturn boolean true si le renommage a réussi
_write_snapshot = (snapshot) ->
  path = file_path!
  return false unless path
  -- Suffixe unique dans le processus : le temporaire ne correspond jamais au
  -- motif `metrics-*.json` lu par la page admin.
  _tmp_seq += 1
  tmp = "#{path}.tmp.#{_tmp_seq}"
  fh = io.open tmp, "w"
  return false unless fh
  ok = pcall ->
    fh\write json.encode snapshot
    fh\close!
  unless ok
    pcall -> fh\close!
    pcall -> os.remove tmp
    return false
  renamed = os.rename tmp, path
  os.remove tmp unless renamed
  renamed and true or false

--- Écrit immédiatement un instantané (démarrage, arrêt, tests).
-- @treturn boolean true si l'écriture a réussi
write_now = ->
  return false unless _enabled
  return false unless _dir and _name
  ok = _write_snapshot get_metrics_json!
  _last_flush = _clock!
  ok

--- Point d'entrée du hot-path : vérifie au plus une fois tous les
-- `check_every` paquets si l'intervalle d'écriture est écoulé.
-- Ne rien allouer ici : un incrément et une comparaison par paquet.
-- @treturn nil
maybe_flush = ->
  return unless _enabled
  _pkt_count += 1
  return if _pkt_count < _check_every
  _pkt_count = 0
  return unless _dir and _name
  now = _clock!
  return if now - _last_flush < _flush_interval
  _last_flush = now
  _write_snapshot get_metrics_json!

--- Clear all metrics (for testing).
clear = ->
  _metrics = {}
  _rule_order = {}

--- Get current metrics state (for testing).
_get_state = ->
  _metrics

{
  :init
  :record_verdict
  :get_metrics_json
  :write_now
  :maybe_flush
  :file_path
  :clear
  :_get_state
}
