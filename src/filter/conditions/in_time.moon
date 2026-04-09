-- src/filter/conditions/in_time.moon
-- Condition : la requête arrive dans une fenêtre horaire nommée.
-- Port de shelterfilter conditions/in_time.moon.
-- La fenêtre est définie dans cfg.times[name] = {"HH:MM", "HH:MM"}.

--- @tparam table cfg Configuration du filtre ({times: {name: {"HH:MM","HH:MM"}}})
-- @treturn function factory (name: string) → (req) → bool, reason
(cfg) -> (name) ->
  times = cfg.times or {}
  window = times[name]
  unless window
    return (req) -> false, "Time window '#{name}' not defined"

  start_s, end_s = window[1], window[2]

  --- @tparam table req {ts: number, ...}  (ts = os.time())
  -- @treturn boolean, string
  (req) ->
    -- ts dans req ou heure courante
    ts = req.ts or os.time!

    -- Date du jour pour construire les bornes
    t = os.date "*t", ts
    year, month, day = t.year, t.month, t.day

    sh, sm = start_s\match "^(%d+):(%d+)$"
    eh, em = end_s\match "^(%d+):(%d+)$"
    return false, "Invalid time window format" unless sh and eh

    _start = os.time { :year, :month, :day, hour: tonumber(sh), min: tonumber(sm), sec: 0 }
    _end   = os.time { :year, :month, :day, hour: tonumber(eh), min: tonumber(em), sec: 0 }

    if _start < ts and ts < _end
      true, "In time window '#{name}' (#{start_s}–#{end_s})"
    else
      false, "Outside time window '#{name}' (#{start_s}–#{end_s})"
