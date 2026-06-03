local LOWMEM_THRESHOLD_DEFAULT_KB = 131072
local read_mem_total_kb
read_mem_total_kb = function(path)
  if path == nil then
    path = "/proc/meminfo"
  end
  local f = io.open(path, "r")
  if not (f) then
    return 0
  end
  local total = 0
  for line in f:lines() do
    local kb = line:match("^MemTotal:%s+(%d+)")
    if kb then
      total = tonumber(kb) or 0
      break
    end
  end
  f:close()
  return total
end
local parse_queues
parse_queues = function(str)
  local queues = { }
  if not (str) then
    return queues
  end
  for part in str:gmatch("%d+%-?%d*") do
    if part:match("%-%d+") then
      local a, b = part:match("(%d+)%-(%d+)")
      a, b = tonumber(a), tonumber(b)
      if a and b then
        if a <= b then
          for n = a, b do
            table.insert(queues, n)
          end
        else
          for n = b, a do
            table.insert(queues, n)
          end
        end
      else
        local n = tonumber(part)
        if n then
          table.insert(queues, n)
        end
      end
    else
      local n = tonumber(part)
      if n then
        table.insert(queues, n)
      end
    end
  end
  return queues
end
local detect
detect = function(runtime_cfg, mem_reader)
  if runtime_cfg == nil then
    runtime_cfg = { }
  end
  if mem_reader == nil then
    mem_reader = read_mem_total_kb
  end
  local _exp_0 = runtime_cfg.lowmem
  if true == _exp_0 or "on" == _exp_0 then
    return true
  elseif false == _exp_0 or "off" == _exp_0 then
    return false
  end
  local threshold = tonumber(runtime_cfg.lowmem_threshold_kb) or LOWMEM_THRESHOLD_DEFAULT_KB
  local mem_kb = mem_reader()
  return mem_kb > 0 and mem_kb < threshold
end
local collapse_nfqueue
collapse_nfqueue = function(nfqueue, keys)
  if keys == nil then
    keys = {
      "questions",
      "responses",
      "captive",
      "reject"
    }
  end
  local collapsed = { }
  for _index_0 = 1, #keys do
    local key = keys[_index_0]
    local qs = parse_queues(nfqueue[key])
    if #qs > 1 then
      local first = tostring(qs[1])
      collapsed[key] = tostring(nfqueue[key]) .. " → " .. tostring(first)
      nfqueue[key] = first
    end
  end
  return collapsed
end
return {
  LOWMEM_THRESHOLD_DEFAULT_KB = LOWMEM_THRESHOLD_DEFAULT_KB,
  read_mem_total_kb = read_mem_total_kb,
  parse_queues = parse_queues,
  detect = detect,
  collapse_nfqueue = collapse_nfqueue
}
