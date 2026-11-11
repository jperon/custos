local config = require("config")
local json = require("lib.json")
local shquote
shquote = require("lib.shquote").shquote
local metrics_cfg = config.metrics or { }
local _metrics = { }
local _rule_order = { }
local _enabled = metrics_cfg.enabled ~= false
local _max_rules = metrics_cfg.max_rules or 1000
local _flush_interval = metrics_cfg.flush_interval or 60
local _dir = nil
local _name = nil
local _clock = os.time
local _check_every = 32
local _pkt_count = 0
local _last_flush = 0
local _tmp_seq = 0
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
    dnsonly_count = 0
  }
  return table.insert(_rule_order, rule_id)
end
local init
init = function(cfg, opts)
  cfg = cfg or { }
  opts = opts or { }
  _enabled = cfg.enabled ~= false
  _max_rules = cfg.max_rules or 1000
  _flush_interval = cfg.flush_interval or 60
  _dir = opts.dir
  _name = opts.name
  _clock = opts.clock or os.time
  _check_every = opts.check_every or 32
  _pkt_count = 0
  _last_flush = 0
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
local get_metrics_json
get_metrics_json = function()
  local rules = { }
  if _enabled then
    for _index_0 = 1, #_rule_order do
      local _continue_0 = false
      repeat
        local rule_id = _rule_order[_index_0]
        local metric = _metrics[rule_id]
        if not (metric) then
          _continue_0 = true
          break
        end
        rules[#rules + 1] = {
          rule_id = rule_id,
          verdicts = {
            allow = metric.allow_count,
            refuse = metric.refuse_count,
            dnsonly = metric.dnsonly_count
          }
        }
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
  end
  return {
    timestamp = _clock(),
    rules = rules
  }
end
local file_path
file_path = function()
  if not (_dir and _name) then
    return nil
  end
  return tostring(_dir) .. "/metrics-" .. tostring(_name) .. ".json"
end
local _write_snapshot
_write_snapshot = function(snapshot)
  local path = file_path()
  if not (path) then
    return false
  end
  _tmp_seq = _tmp_seq + 1
  local tmp = tostring(path) .. ".tmp." .. tostring(_tmp_seq)
  local fh = io.open(tmp, "w")
  if not (fh) then
    return false
  end
  local ok = pcall(function()
    fh:write(json.encode(snapshot))
    return fh:close()
  end)
  if not (ok) then
    pcall(function()
      return fh:close()
    end)
    pcall(function()
      return os.remove(tmp)
    end)
    return false
  end
  local renamed = os.rename(tmp, path)
  if not (renamed) then
    os.remove(tmp)
  end
  return renamed and true or false
end
local write_now
write_now = function()
  if not (_enabled) then
    return false
  end
  if not (_dir and _name) then
    return false
  end
  local ok = _write_snapshot(get_metrics_json())
  _last_flush = _clock()
  return ok
end
local purge_files
purge_files = function(dir)
  if not (dir) then
    return 0
  end
  local h = io.popen("ls -1 " .. tostring(shquote(dir)) .. "/metrics-*.json " .. tostring(shquote(dir)) .. "/metrics-*.json.tmp.* 2>/dev/null")
  if not (h) then
    return 0
  end
  local removed = 0
  for path in h:lines() do
    if os.remove(path) then
      removed = removed + 1
    end
  end
  h:close()
  return removed
end
local flush_if_due
flush_if_due = function()
  if not (_enabled) then
    return false
  end
  if not (_dir and _name) then
    return false
  end
  local now = _clock()
  if now - _last_flush < _flush_interval then
    return false
  end
  _last_flush = now
  return _write_snapshot(get_metrics_json())
end
local maybe_flush
maybe_flush = function()
  if not (_enabled) then
    return 
  end
  _pkt_count = _pkt_count + 1
  if _pkt_count < _check_every then
    return 
  end
  _pkt_count = 0
  return flush_if_due()
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
  get_metrics_json = get_metrics_json,
  write_now = write_now,
  purge_files = purge_files,
  flush_if_due = flush_if_due,
  maybe_flush = maybe_flush,
  file_path = file_path,
  clear = clear,
  _get_state = _get_state
}
