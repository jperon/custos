local bit = require("bit")
local is_array
is_array = function(t)
  if not (type(t) == "table") then
    return false
  end
  local n = #t
  if n == 0 then
    return false
  end
  for i = 1, n do
    if t[i] == nil then
      return false
    end
  end
  return true
end
local parse_time_str
parse_time_str = function(s)
  if not (type(s) == "string") then
    return nil
  end
  local h, m = s:match("^(%d+):(%d+)$")
  if not (h and m) then
    return nil
  end
  local h_num, m_num = tonumber(h), tonumber(m)
  if h_num < 0 or h_num > 23 or m_num < 0 or m_num > 59 then
    return nil
  end
  return {
    hour = h_num,
    min = m_num,
    str = s
  }
end
local day_name_to_wday
day_name_to_wday = function(name)
  local map = {
    Sun = 1,
    Mon = 2,
    Tue = 3,
    Wed = 4,
    Thu = 5,
    Fri = 6,
    Sat = 7
  }
  return map[name]
end
local build_day_bitmask
build_day_bitmask = function(days)
  if not (type(days) == "table") then
    return 0x7f
  end
  if #days == 0 then
    return 0x7f
  end
  local mask = 0
  for _, day_name in ipairs(days) do
    local wday = day_name_to_wday(day_name)
    if not (wday) then
      return nil
    end
    mask = bit.bor(mask, bit.lshift(1, wday - 1))
  end
  return mask
end
return function(cfg)
  return function(spec)
    local times = cfg.times or { }
    local start_s, end_s, day_bitmask = nil, nil, nil
    local desc_str = nil
    if type(spec) == "string" then
      local window = times[spec]
      if not (window) then
        return function(req)
          return false, "Time window '" .. tostring(spec) .. "' not defined"
        end
      end
      start_s, end_s = window[1], window[2]
      desc_str = "'" .. tostring(spec) .. "'"
    elseif type(spec) == "table" then
      start_s = spec.start
      end_s = spec["end"]
      local days = spec.days
      if not (start_s and end_s) then
        return function(req)
          return false, "Inline time spec requires 'start' and 'end'"
        end
      end
      day_bitmask = build_day_bitmask(days)
      if not (day_bitmask) then
        return function(req)
          return false, "Invalid day names in inline time spec"
        end
      end
      local day_desc
      if days then
        day_desc = table.concat(days, ",")
      else
        day_desc = "daily"
      end
      desc_str = tostring(start_s) .. "–" .. tostring(end_s) .. " (" .. tostring(day_desc) .. ")"
    else
      return function(req)
        return false, "Time window spec must be string or table"
      end
    end
    local start_parsed = parse_time_str(start_s)
    local end_parsed = parse_time_str(end_s)
    if not (start_parsed and end_parsed) then
      return function(req)
        return false, "Invalid time window format (expected HH:MM)"
      end
    end
    return function(req)
      local ts = req.ts or os.time()
      local t = os.date("*t", ts)
      local year, month, day = t.year, t.month, t.day
      local wday = t.wday
      if day_bitmask then
        if not (bit.band(day_bitmask, bit.lshift(1, wday - 1)) > 0) then
          return false, "Outside time window " .. tostring(desc_str) .. " (not a matching day)"
        end
      end
      local _start = os.time({
        year = year,
        month = month,
        day = day,
        hour = start_parsed.hour,
        min = start_parsed.min,
        sec = 0
      })
      local _end = os.time({
        year = year,
        month = month,
        day = day,
        hour = end_parsed.hour,
        min = end_parsed.min,
        sec = 0
      })
      if _start < ts and ts < _end then
        return true, "In time window " .. tostring(desc_str)
      else
        return false, "Outside time window " .. tostring(desc_str)
      end
    end
  end
end
