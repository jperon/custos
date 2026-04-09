return function(cfg)
  return function(name)
    local times = cfg.times or { }
    local window = times[name]
    if not (window) then
      return function(req)
        return false, "Time window '" .. tostring(name) .. "' not defined"
      end
    end
    local start_s, end_s = window[1], window[2]
    return function(req)
      local ts = req.ts or os.time()
      local t = os.date("*t", ts)
      local year, month, day = t.year, t.month, t.day
      local sh, sm = start_s:match("^(%d+):(%d+)$")
      local eh, em = end_s:match("^(%d+):(%d+)$")
      if not (sh and eh) then
        return false, "Invalid time window format"
      end
      local _start = os.time({
        year = year,
        month = month,
        day = day,
        hour = tonumber(sh),
        min = tonumber(sm),
        sec = 0
      })
      local _end = os.time({
        year = year,
        month = month,
        day = day,
        hour = tonumber(eh),
        min = tonumber(em),
        sec = 0
      })
      if _start < ts and ts < _end then
        return true, "In time window '" .. tostring(name) .. "' (" .. tostring(start_s) .. "–" .. tostring(end_s) .. ")"
      else
        return false, "Outside time window '" .. tostring(name) .. "' (" .. tostring(start_s) .. "–" .. tostring(end_s) .. ")"
      end
    end
  end
end
