local DEFAULT_IFNAME = "br0"
local read_lines
read_lines = function(cmd, popen)
  popen = popen or io.popen
  local handle = popen(cmd)
  if not (handle) then
    return { }
  end
  local out = { }
  for line in handle:lines() do
    local name = line:match("^%s*(%S+)")
    if name then
      out[#out + 1] = name
    end
  end
  handle:close()
  return out
end
local list_bridges
list_bridges = function(popen)
  local out = { }
  local _list_0 = read_lines("ls -d /sys/class/net/*/bridge 2>/dev/null", popen)
  for _index_0 = 1, #_list_0 do
    local path = _list_0[_index_0]
    local name = path:match("/sys/class/net/([^/]+)/bridge")
    if name then
      out[#out + 1] = name
    end
  end
  if #out > 0 then
    return out
  end
  return read_lines("ip -brief link show type bridge 2>/dev/null", popen)
end
local count_slaves
count_slaves = function(name, popen)
  return #read_lines("ls -1 /sys/class/net/" .. tostring(name) .. "/brif/ 2>/dev/null", popen)
end
local tiebreak_rank
tiebreak_rank = function(name)
  if name == "br-lan" then
    return 2
  end
  if name == DEFAULT_IFNAME then
    return 1
  end
  return 0
end
local pick_bridge
pick_bridge = function(names, count_fn)
  if not names or #names == 0 then
    return nil
  end
  count_fn = count_fn or count_slaves
  local best, best_slaves, best_rank = nil, -1, -1
  local sorted
  do
    local _accum_0 = { }
    local _len_0 = 1
    for _index_0 = 1, #names do
      local n = names[_index_0]
      _accum_0[_len_0] = n
      _len_0 = _len_0 + 1
    end
    sorted = _accum_0
  end
  table.sort(sorted)
  for _index_0 = 1, #sorted do
    local name = sorted[_index_0]
    local slaves = count_fn(name)
    local rank = tiebreak_rank(name)
    if slaves > best_slaves or (slaves == best_slaves and rank > best_rank) then
      best, best_slaves, best_rank = name, slaves, rank
    end
  end
  return best
end
local valid_name
valid_name = function(name)
  if not (name and #name > 0 and #name <= 15) then
    return false
  end
  return not not name:match("^[%w%.%-_]+$")
end
local exists
exists = function(name)
  if not (name and #name > 0) then
    return false
  end
  local fh = io.open("/sys/class/net/" .. tostring(name) .. "/operstate", "r")
  if fh then
    fh:close()
    return true
  end
  local fh2 = io.open("/sys/class/net/" .. tostring(name) .. "/ifindex", "r")
  if fh2 then
    fh2:close()
    return true
  end
  return false
end
local detect
detect = function(opts)
  opts = opts or { }
  local env = os.getenv("BRIDGE_IFNAME")
  if env and #env > 0 then
    if valid_name(env) then
      return env
    end
    io.stderr:write("bridge_detect: BRIDGE_IFNAME invalide ignoré: " .. tostring(env) .. "\n")
  end
  return pick_bridge(list_bridges(opts.popen), opts.count_fn) or DEFAULT_IFNAME
end
return {
  DEFAULT_IFNAME = DEFAULT_IFNAME,
  read_lines = read_lines,
  list_bridges = list_bridges,
  count_slaves = count_slaves,
  pick_bridge = pick_bridge,
  valid_name = valid_name,
  exists = exists,
  detect = detect
}
