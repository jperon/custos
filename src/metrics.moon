-- src/metrics.moon
-- Per-rule performance metrics collection and aggregation.
-- Tracks verdicts (allow, refuse, dnsonly), cache hits/misses, and TTL statistics.
-- Memory bounded with LRU eviction if >1000 rules.
-- Zero-overhead when disabled.

config = require "config"

metrics_cfg = config.metrics or {}

_metrics = {}
_rule_order = {}
_enabled = metrics_cfg.enabled or true
_max_rules = metrics_cfg.max_rules or 1000

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
    cache_hits:    0
    cache_misses:  0
    ttl_samples:   {}
  }

  table.insert _rule_order, rule_id

--- Calculate cache hit rate for a rule.
_get_hit_rate = (rule_id) ->
  metric = _metrics[rule_id]
  return 0 unless metric

  total = metric.cache_hits + metric.cache_misses
  return 0 if total == 0
  (metric.cache_hits / total) * 100

--- Calculate TTL statistics for a rule.
_get_ttl_stats = (rule_id) ->
  metric = _metrics[rule_id]
  return { min: 0, max: 0, avg: 0 } unless metric and #metric.ttl_samples > 0

  samples = metric.ttl_samples
  min_val = samples[1]
  max_val = samples[1]
  sum = 0

  for s in *samples
    min_val = math.min min_val, s
    max_val = math.max max_val, s
    sum += s

  avg = math.floor(sum / #samples)
  { min: min_val, max: max_val, avg: avg }

--- Initialize metrics module with optional config override.
init = (cfg) ->
  cfg or= {}
  _enabled = cfg.enabled != false
  _max_rules = cfg.max_rules or 1000

--- Record a verdict for a rule.
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

--- Record a cache hit or miss for a rule.
record_cache = (rule_id, hit) ->
  return unless _enabled
  return unless rule_id

  _ensure_rule_entry rule_id

  if hit
    _metrics[rule_id].cache_hits += 1
  else
    _metrics[rule_id].cache_misses += 1

--- Record a TTL value for a rule.
record_ttl = (rule_id, ttl_seconds) ->
  return unless _enabled
  return unless rule_id and type(ttl_seconds) == "number"

  _ensure_rule_entry rule_id

  samples = _metrics[rule_id].ttl_samples
  table.insert samples, ttl_seconds

  -- Keep only last 100 samples per rule
  if #samples > 100
    table.remove samples, 1

--- Get metrics as JSON-exportable table.
get_metrics_json = ->
  return {
    timestamp: os.time!
    rules: {}
  } unless _enabled or #_rule_order == 0

  rules = {}
  for rule_id in *_rule_order
    metric = _metrics[rule_id]
    continue unless metric

    hit_rate = _get_hit_rate rule_id
    ttl_stats = _get_ttl_stats rule_id

    rules[#rules + 1] = {
      rule_id:  rule_id
      verdicts: {
        allow:    metric.allow_count
        refuse:   metric.refuse_count
        dnsonly:  metric.dnsonly_count
      }
      cache: {
        hits:     metric.cache_hits
        misses:   metric.cache_misses
        hit_rate: hit_rate
      }
      ttl: ttl_stats
    }

  {
    timestamp: os.time!
    rules: rules
  }

--- Flush and reset all metrics.
flush_metrics = ->
  return {} unless _enabled

  snapshot = get_metrics_json!
  _metrics = {}
  _rule_order = {}
  snapshot

--- Get current metrics snapshot without flushing.
get_snapshot = ->
  get_metrics_json!

--- Get a specific rule's metrics.
get_rule_metrics = (rule_id) ->
  return nil unless rule_id
  metric = _metrics[rule_id]
  return nil unless metric

  hit_rate = _get_hit_rate rule_id
  ttl_stats = _get_ttl_stats rule_id

  {
    rule_id:  rule_id
    verdicts: {
      allow:    metric.allow_count
      refuse:   metric.refuse_count
      dnsonly:  metric.dnsonly_count
    }
    cache: {
      hits:     metric.cache_hits
      misses:   metric.cache_misses
      hit_rate: hit_rate
    }
    ttl: ttl_stats
  }

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
  :record_cache
  :record_ttl
  :flush_metrics
  :get_metrics_json
  :get_snapshot
  :get_rule_metrics
  :clear
  :_get_state
  :_get_hit_rate
  :_get_ttl_stats
}
