local floor = math.floor
local ceil = math.ceil
local sort = table.sort
local concat = table.concat
local fmt = string.format
local percentiles
percentiles = function(samples)
  local n = #samples
  if n == 0 then
    return {
      p50 = 0,
      p95 = 0,
      p99 = 0,
      min = 0,
      max = 0,
      count = 0
    }
  end
  local copy
  do
    local _accum_0 = { }
    local _len_0 = 1
    for _index_0 = 1, #samples do
      local v = samples[_index_0]
      _accum_0[_len_0] = v
      _len_0 = _len_0 + 1
    end
    copy = _accum_0
  end
  sort(copy)
  local pick
  pick = function(q)
    return copy[math.max(1, math.min(n, ceil(q * n)))]
  end
  return {
    p50 = pick(0.50),
    p95 = pick(0.95),
    p99 = pick(0.99),
    min = copy[1],
    max = copy[n],
    count = n
  }
end
local _ser
_ser = function(v)
  local t = type(v)
  if t == "table" then
    local parts = { }
    local is_seq = true
    local cnt = 0
    for _ in pairs(v) do
      cnt = cnt + 1
    end
    is_seq = cnt == #v and cnt > 0
    if is_seq then
      for _index_0 = 1, #v do
        local item = v[_index_0]
        parts[#parts + 1] = _ser(item)
      end
    else
      local keys
      do
        local _accum_0 = { }
        local _len_0 = 1
        for k in pairs(v) do
          _accum_0[_len_0] = k
          _len_0 = _len_0 + 1
        end
        keys = _accum_0
      end
      sort(keys, function(a, b)
        return tostring(a) < tostring(b)
      end)
      for _index_0 = 1, #keys do
        local k = keys[_index_0]
        parts[#parts + 1] = "[" .. _ser(k) .. "]=" .. _ser(v[k])
      end
    end
    return "{" .. concat(parts, ",") .. "}"
  elseif t == "string" then
    return fmt("%q", v)
  elseif t == "number" or t == "boolean" then
    return tostring(v)
  else
    return "nil"
  end
end
local serialize
serialize = function(result)
  return "return " .. _ser(result)
end
local deserialize
deserialize = function(s)
  local loader = loadstring or load
  local chunk, err = loader(s, "baseline")
  if not (chunk) then
    return nil, "chargement impossible : " .. tostring(err)
  end
  local ok, val = pcall(chunk)
  if not (ok) then
    return nil, "évaluation impossible : " .. tostring(val)
  end
  if not (type(val) == "table") then
    return nil, "la baseline n'est pas une table"
  end
  return val
end
local deltas
deltas = function(cur, base)
  local out = { }
  for k, v in pairs(cur) do
    local _continue_0 = false
    repeat
      local bv = base[k]
      if not (type(v) == "number" and type(bv) == "number") then
        _continue_0 = true
        break
      end
      if bv == 0 then
        _continue_0 = true
        break
      end
      out[k] = (v - bv) / bv * 100
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return out
end
local _fmt_delta
_fmt_delta = function(d)
  return d and fmt(" (%+.1f%%)", d) or ""
end
local format
format = function(result, baseline)
  local lines = { }
  local add
  add = function(s)
    lines[#lines + 1] = s
  end
  add("=== CustosVirginum — rapport de benchmark ===")
  add("date : " .. (result.ts or "?"))
  if result.micro then
    add("")
    add("--- micro-bench (in-process) ---")
    local base_by_name = { }
    if baseline and baseline.micro then
      local _list_0 = baseline.micro
      for _index_0 = 1, #_list_0 do
        local c = _list_0[_index_0]
        base_by_name[c.name] = c
      end
    end
    local _list_0 = result.micro
    for _index_0 = 1, #_list_0 do
      local c = _list_0[_index_0]
      local d = nil
      do
        local bc = base_by_name[c.name]
        if bc then
          local dd = deltas({
            ns = c.ns_per_op
          }, {
            ns = bc.ns_per_op
          })
          d = dd.ns
        end
      end
      add(fmt("%-46s %10.1f ns/op   ~%7.0f KB%s", c.name, c.ns_per_op, c.kb_alloc, _fmt_delta(d)))
    end
  end
  if result.load then
    local l = result.load
    local bl = baseline and baseline.load
    add("")
    add("--- charge DNS (bout-en-bout) ---")
    local show
    show = function(label, key, unit)
      if unit == nil then
        unit = ""
      end
      local d = bl and (deltas({
        x = l[key]
      }, {
        x = bl[key]
      })).x or nil
      return add(fmt("  %-22s %12.2f %s%s", label, l[key] or 0, unit, _fmt_delta(d)))
    end
    show("qps", "qps")
    show("sent", "sent")
    show("received", "received")
    show("dropped", "dropped")
    show("timeouts", "timeouts")
    show("latence p50", "p50", "ms")
    show("latence p95", "p95", "ms")
    show("latence p99", "p99", "ms")
  end
  return concat(lines, "\n")
end
return {
  percentiles = percentiles,
  serialize = serialize,
  deserialize = deserialize,
  deltas = deltas,
  format = format
}
