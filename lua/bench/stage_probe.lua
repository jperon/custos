local new
new = function()
  local probes = { }
  local order = { }
  local register
  register = function(label)
    local p = (probes[label] or {
      label = label,
      time = 0,
      alloc = 0,
      calls = 0
    })
    if not (probes[label]) then
      probes[label] = p
      order[#order + 1] = label
    end
    return p
  end
  local probe_fn
  probe_fn = function(label, fn)
    local p = register(label)
    return function(...)
      local t0 = os.clock()
      local a0 = collectgarbage("count")
      local r1, r2, r3, r4, r5 = fn(...)
      p.time = p.time + (os.clock() - t0)
      p.alloc = p.alloc + ((collectgarbage("count")) - a0)
      p.calls = p.calls + 1
      return r1, r2, r3, r4, r5
    end
  end
  local wrap
  wrap = function(mod, field, label)
    if not (type(mod) == "table" and type(mod[field]) == "function") then
      return false
    end
    mod[field] = probe_fn(label, mod[field])
    return true
  end
  local wrap_state
  wrap_state = function(mod, field, labels)
    if not (type(mod) == "table" and type(mod[field]) == "function") then
      return false
    end
    local orig = mod[field]
    mod[field] = function(...)
      local st = orig(...)
      for _index_0 = 1, #labels do
        local label = labels[_index_0]
        if type(st) == "table" and type(st[label]) == "function" then
          st[label] = probe_fn("so." .. tostring(label), st[label])
        end
      end
      return st
    end
    return true
  end
  local reset
  reset = function()
    for _, p in pairs(probes) do
      p.time = 0
      p.alloc = 0
      p.calls = 0
    end
    return nil
  end
  local results
  results = function(iters)
    local out = { }
    local n = iters > 0 and iters or 1
    for _index_0 = 1, #order do
      local label = order[_index_0]
      local p = probes[label]
      out[#out + 1] = {
        label = label,
        us = p.time * 1e6 / n,
        bytes = p.alloc * 1024 / n,
        calls = p.calls,
        calls_req = p.calls / n,
        us_call = p.calls > 0 and (p.time * 1e6 / p.calls) or 0
      }
    end
    table.sort(out, function(a, b)
      return a.us > b.us
    end)
    return out
  end
  local labels
  labels = function()
    local _accum_0 = { }
    local _len_0 = 1
    for _index_0 = 1, #order do
      local p = order[_index_0]
      _accum_0[_len_0] = p
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end
  return {
    wrap = wrap,
    wrap_state = wrap_state,
    reset = reset,
    results = results,
    labels = labels
  }
end
return {
  new = new
}
