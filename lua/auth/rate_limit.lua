local with_lock
with_lock = require("lib.filelock").with_lock
local ffi
ffi = require("ffi_defs").ffi
local DEFAULT_LIMIT = 3
local DEFAULT_WINDOW = 300
local MAX_ENTRIES = 4096
local os_time = os.time
local os_rename = os.rename
local key_for
key_for = function(peer_mac, peer_ip)
  local mac = peer_mac and tostring(peer_mac)
  if mac and mac ~= "" and mac ~= "unknown" then
    return "mac:" .. mac:lower()
  else
    local ip = peer_ip and tostring(peer_ip)
    if ip and ip ~= "" then
      return "ip:" .. ip:lower()
    else
      return "unknown"
    end
  end
end
local parse_state
parse_state = function(content)
  local entries = { }
  for line in tostring(content):gmatch("[^\n]+") do
    local key, count, reset_at = line:match("^([^\t]+)\t(%d+)\t(%d+)$")
    if key then
      entries[key] = {
        count = tonumber(count),
        reset_at = tonumber(reset_at)
      }
    end
  end
  return entries
end
local load_state
load_state = function(path)
  if not (path) then
    return { }
  end
  local fh = io.open(path, "r")
  if not (fh) then
    return { }
  end
  local content = fh:read("*a")
  fh:close()
  if not (content) then
    return { }
  end
  local ok, entries = pcall(parse_state, content)
  if not (ok and type(entries) == "table") then
    return { }
  end
  return entries
end
local serialize_state
serialize_state = function(entries)
  local keys
  do
    local _accum_0 = { }
    local _len_0 = 1
    for k in pairs(entries) do
      _accum_0[_len_0] = k
      _len_0 = _len_0 + 1
    end
    keys = _accum_0
  end
  table.sort(keys)
  local parts = { }
  for _index_0 = 1, #keys do
    local key = keys[_index_0]
    local entry = entries[key]
    parts[#parts + 1] = string.format("%s\t%d\t%d\n", key, entry.count, entry.reset_at)
  end
  return table.concat(parts)
end
local write_state
write_state = function(entries, path)
  local tmp_path = path .. ".new." .. tostring(ffi.C.getpid())
  local fh, err = io.open(tmp_path, "w")
  if not (fh) then
    os.remove(tmp_path)
    return false, err
  end
  fh:write(serialize_state(entries))
  fh:close()
  local ok, err2 = os_rename(tmp_path, path)
  if not (ok) then
    os.remove(tmp_path)
    return false, err2
  end
  return true
end
local trim
trim = function(entries, max_entries)
  local keys
  do
    local _accum_0 = { }
    local _len_0 = 1
    for k in pairs(entries) do
      _accum_0[_len_0] = k
      _len_0 = _len_0 + 1
    end
    keys = _accum_0
  end
  local excess = #keys - max_entries
  if excess <= 0 then
    return 
  end
  table.sort(keys, function(a, b)
    return entries[a].reset_at < entries[b].reset_at
  end)
  for i = 1, excess do
    entries[keys[i]] = nil
  end
end
local check
check = function(path, key, limit, window, now)
  limit = tonumber(limit) or DEFAULT_LIMIT
  window = tonumber(window) or DEFAULT_WINDOW
  if window <= 0 then
    window = DEFAULT_WINDOW
  end
  if not (limit > 0 and path) then
    return true, 0, math.max(0, limit)
  end
  key = key or "unknown"
  now = tonumber(now) or os_time()
  local allowed, retry_after, remaining = true, 0, math.max(0, limit)
  local ok = pcall(function()
    return with_lock(path .. ".lock", function()
      local entries = load_state(path)
      for k, entry in pairs(entries) do
        if not entry.reset_at or entry.reset_at <= now then
          entries[k] = nil
        end
      end
      local current = entries[key]
      if current and current.count >= limit then
        allowed = false
        retry_after = math.max(1, math.ceil(current.reset_at - now))
        write_state(entries, path)
        return 
      end
      if not (current) then
        current = {
          count = 0,
          reset_at = now + window
        }
        entries[key] = current
      end
      current.count = current.count + 1
      remaining = math.max(0, limit - current.count)
      trim(entries, MAX_ENTRIES)
      return write_state(entries, path)
    end)
  end)
  if not (ok) then
    return true, 0, math.max(0, limit)
  end
  return allowed, retry_after, remaining
end
return {
  check = check,
  key_for = key_for,
  parse_state = parse_state,
  serialize_state = serialize_state,
  DEFAULT_LIMIT = DEFAULT_LIMIT,
  DEFAULT_WINDOW = DEFAULT_WINDOW,
  MAX_ENTRIES = MAX_ENTRIES
}
