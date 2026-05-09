local config = require("config")
local metrics_cfg = config.metrics or { }
local _metrics = { }
local _rule_order = { }
local _enabled = metrics_cfg.enabled or true
local _max_rules = metrics_cfg.max_rules or 1000
local _ensure_rule_entry
_ensure_rule_entry = function(rule_id)
  if _metrics[rule_id] then
    return 
  end
  if #_rule_order >= _max_rules then
    local lru_rule = table.remove(_rule_order, 1)
    _metrics[lru_rule] = nil
  end
  _metrics[rule_id] = {
    allow_count = 0,
    refuse_count = 0,
    dnsonly_count = 0,
    cache_hits = 0,
    cache_misses = 0,
    ttl_samples = { }
  }
  return table.insert(_rule_order, rule_id)
end
local _get_hit_rate
_get_hit_rate = function(rule_id)
  local metric = _metrics[rule_id]
  if not (metric) then
    return 0
  end
  local total = metric.cache_hits + metric.cache_misses
  if total == 0 then
    return 0
  end
  return (metric.cache_hits / total) * 100
end
local _get_ttl_stats
_get_ttl_stats = function(rule_id)
  local metric = _metrics[rule_id]
  if not (metric and #metric.ttl_samples > 0) then
    return {
      min = 0,
      max = 0,
      avg = 0
    }
  end
  local samples = metric.ttl_samples
  local min_val = samples[1]
  local max_val = samples[1]
  local sum = 0
  for _index_0 = 1, #samples do
    local s = samples[_index_0]
    min_val = math.min(min_val, s)
    max_val = math.max(max_val, s)
    sum = sum + s
  end
  local avg = math.floor(sum / #samples)
  return {
    min = min_val,
    max = max_val,
    avg = avg
  }
end
local init
init = function(cfg)
  cfg = cfg or { }
  _enabled = cfg.enabled ~= false
  _max_rules = cfg.max_rules or 1000
end
local record_verdict
record_verdict = function(rule_id, verdict)
  if not (_enabled) then
    return 
  end
  if not (rule_id and verdict) then
    return 
  end
  _ensure_rule_entry(rule_id)
  if verdict == "allow" then
    local _update_0 = rule_id
    _metrics[_update_0].allow_count = _metrics[_update_0].allow_count + 1
  elseif verdict == "refuse" then
    local _update_0 = rule_id
    _metrics[_update_0].refuse_count = _metrics[_update_0].refuse_count + 1
  elseif verdict == "dnsonly" then
    local _update_0 = rule_id
    _metrics[_update_0].dnsonly_count = _metrics[_update_0].dnsonly_count + 1
  end
end
local record_cache
record_cache = function(rule_id, hit)
  if not (_enabled) then
    return 
  end
  if not (rule_id) then
    return 
  end
  _ensure_rule_entry(rule_id)
  if hit then
    local _update_0 = rule_id
    _metrics[_update_0].cache_hits = _metrics[_update_0].cache_hits + 1
  else
    local _update_0 = rule_id
    _metrics[_update_0].cache_misses = _metrics[_update_0].cache_misses + 1
  end
end
local record_ttl
record_ttl = function(rule_id, ttl_seconds)
  if not (_enabled) then
    return 
  end
  if not (rule_id and type(ttl_seconds) == "number") then
    return 
  end
  _ensure_rule_entry(rule_id)
  local samples = _metrics[rule_id].ttl_samples
  table.insert(samples, ttl_seconds)
  if #samples > 100 then
    return table.remove(samples, 1)
  end
end
local get_metrics_json
get_metrics_json = function()
  if not (_enabled or #_rule_order == 0) then
    return {
      timestamp = os.time(),
      rules = { }
    }
  end
  local rules = { }
  for _index_0 = 1, #_rule_order do
    local _continue_0 = false
    repeat
      local rule_id = _rule_order[_index_0]
      local metric = _metrics[rule_id]
      if not (metric) then
        _continue_0 = true
        break
      end
      local hit_rate = _get_hit_rate(rule_id)
      local ttl_stats = _get_ttl_stats(rule_id)
      rules[#rules + 1] = {
        rule_id = rule_id,
        verdicts = {
          allow = metric.allow_count,
          refuse = metric.refuse_count,
          dnsonly = metric.dnsonly_count
        },
        cache = {
          hits = metric.cache_hits,
          misses = metric.cache_misses,
          hit_rate = hit_rate
        },
        ttl = ttl_stats
      }
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return {
    timestamp = os.time(),
    rules = rules
  }
end
local flush_metrics
flush_metrics = function()
  if not (_enabled) then
    return { }
  end
  local snapshot = get_metrics_json()
  _metrics = { }
  _rule_order = { }
  return snapshot
end
local get_snapshot
get_snapshot = function()
  return get_metrics_json()
end
local get_rule_metrics
get_rule_metrics = function(rule_id)
  if not (rule_id) then
    return nil
  end
  local metric = _metrics[rule_id]
  if not (metric) then
    return nil
  end
  local hit_rate = _get_hit_rate(rule_id)
  local ttl_stats = _get_ttl_stats(rule_id)
  return {
    rule_id = rule_id,
    verdicts = {
      allow = metric.allow_count,
      refuse = metric.refuse_count,
      dnsonly = metric.dnsonly_count
    },
    cache = {
      hits = metric.cache_hits,
      misses = metric.cache_misses,
      hit_rate = hit_rate
    },
    ttl = ttl_stats
  }
end
local clear
clear = function()
  _metrics = { }
  _rule_order = { }
end
local _get_state
_get_state = function()
  return _metrics
end
return {
  init = init,
  record_verdict = record_verdict,
  record_cache = record_cache,
  record_ttl = record_ttl,
  flush_metrics = flush_metrics,
  get_metrics_json = get_metrics_json,
  get_snapshot = get_snapshot,
  get_rule_metrics = get_rule_metrics,
  clear = clear,
  _get_state = _get_state,
  _get_hit_rate = _get_hit_rate,
  _get_ttl_stats = _get_ttl_stats
}
