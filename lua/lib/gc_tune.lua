local DEFAULTS = {
  pause = 200,
  stepmul = 400,
  idle_step = 100,
  max_heap_mb = 32
}
local MIN = {
  pause = 0,
  stepmul = 1,
  idle_step = 0,
  max_heap_mb = 0
}
local MAX = {
  pause = 10000,
  stepmul = 100000,
  idle_step = 100000,
  max_heap_mb = 65536
}
local HEAP_CHECK_INTERVAL = 1
local LOG_INTERVAL = 10
local MAX_FORCE_STEPS = 8
local FORCE_STEP = 200
local int_value
int_value = function(raw, default, lo, hi)
  if raw == nil then
    return nil
  end
  local n = tonumber(raw)
  if n == nil then
    return nil
  end
  n = math.floor(n)
  if n < lo or n > hi then
    return nil
  end
  return n
end
local normalize
normalize = function(section)
  if not (type(section) == "table") then
    section = { }
  end
  local values = { }
  local invalid = { }
  local _list_0 = {
    "pause",
    "stepmul",
    "idle_step",
    "max_heap_mb"
  }
  for _index_0 = 1, #_list_0 do
    local key = _list_0[_index_0]
    local raw = section[key]
    local v = int_value(raw, DEFAULTS[key], MIN[key], MAX[key])
    if v == nil then
      values[key] = DEFAULTS[key]
      if raw ~= nil then
        invalid[#invalid + 1] = key
      end
    else
      values[key] = v
    end
  end
  return values, invalid
end
local new
new = function(section, deps)
  local values = normalize(section)
  local gc = (deps and deps.gc) or collectgarbage
  local clock = (deps and deps.clock) or os.time
  local warn = deps and deps.warn
  if not (warn) then
    warn = function(fields)
      local log_warn
      log_warn = require("log").log_warn
      return log_warn(function()
        return fields
      end)
    end
  end
  local state = {
    last_check = nil,
    last_log = nil,
    forced = 0
  }
  local api = {
    values = values
  }
  api.apply = function()
    gc("setpause", values.pause)
    gc("setstepmul", values.stepmul)
    return true
  end
  api.idle = function()
    if not (values.idle_step > 0) then
      return false
    end
    gc("step", values.idle_step)
    return true
  end
  api.guard = function(now)
    if not (values.max_heap_mb > 0) then
      return 0
    end
    if not (now) then
      now = clock()
    end
    if state.last_check and now - state.last_check < HEAP_CHECK_INTERVAL then
      return 0
    end
    state.last_check = now
    local limit_kb = values.max_heap_mb * 1024
    local used = gc("count")
    if used <= limit_kb then
      return 0
    end
    local steps = 0
    while steps < MAX_FORCE_STEPS do
      gc("step", FORCE_STEP)
      steps = steps + 1
      used = gc("count")
      if used <= limit_kb then
        break
      end
    end
    state.forced = state.forced + 1
    if not state.last_log or now - state.last_log >= LOG_INTERVAL then
      state.last_log = now
      warn({
        action = "gc_heap_guard",
        heap_kb = used,
        max_heap_mb = values.max_heap_mb,
        steps = steps
      })
    end
    return steps
  end
  return api
end
local _shared = nil
local shared
shared = function()
  if not (_shared) then
    local section = (require("config")).gc or { }
    _shared = new(section)
  end
  return _shared
end
local reset
reset = function()
  _shared = nil
end
return {
  DEFAULTS = DEFAULTS,
  MIN = MIN,
  MAX = MAX,
  HEAP_CHECK_INTERVAL = HEAP_CHECK_INTERVAL,
  LOG_INTERVAL = LOG_INTERVAL,
  MAX_FORCE_STEPS = MAX_FORCE_STEPS,
  FORCE_STEP = FORCE_STEP,
  normalize = normalize,
  new = new,
  shared = shared,
  reset = reset
}
