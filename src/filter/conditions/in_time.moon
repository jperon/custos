-- src/filter/conditions/in_time.moon
-- Condition : la requête arrive dans une fenêtre horaire nommée ou inline.
-- Port de shelterfilter conditions/in_time.moon (étendu avec support de jours).
-- Syntaxe :
--   - Nommée : cfg.times[name] = {"HH:MM", "HH:MM"}
--   - Inline : { start: "HH:MM", end: "HH:MM", days: ["Mon", "Tue", ...] }

bit = require "bit"

is_array = (t) ->
  return false unless type(t) == "table"
  n = #t
  return false if n == 0
  for i = 1, n
    return false if t[i] == nil
  true

parse_time_str = (s) ->
  return nil unless type(s) == "string"
  h, m = s\match "^(%d+):(%d+)$"
  return nil unless h and m
  h_num, m_num = tonumber(h), tonumber(m)
  return nil if h_num < 0 or h_num > 23 or m_num < 0 or m_num > 59
  { hour: h_num, min: m_num, str: s }

day_name_to_wday = (name) ->
  map = {
    Sun: 1, Mon: 2, Tue: 3, Wed: 4, Thu: 5, Fri: 6, Sat: 7
  }
  map[name]

build_day_bitmask = (days) ->
  -- If days is nil or not a table, treat as all days
  return 0x7f unless type(days) == "table"
  -- If empty table, treat as all days
  return 0x7f if #days == 0
  -- Build bitmask from day names
  mask = 0
  for _, day_name in ipairs days
    wday = day_name_to_wday day_name
    return nil unless wday  -- invalid day name
    mask = bit.bor(mask, bit.lshift(1, wday - 1))
  mask

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (spec: string|table) → enriched_condition
-- Note: in_time is worker-only. nftables has 'time' extension but it's not standard.
-- Future: could compile to 'meta hour >= X hour < Y' with nftables time extension.

_schema = {
  label:       "Plage horaire"
  description: "Requête dans une fenêtre horaire nommée ou inline"
  category:    "time"
  arg_type:    "string_or_table"
  arg_hint:    "nom défini dans filter.times ou {start:'08:00',end:'18:00'}"
}

_factory = (cfg) ->
  (spec) ->
    times = cfg.times or {}
    
    -- Parse spec: either string (named window) or table (inline)
    start_s, end_s, day_bitmask = nil, nil, nil
    desc_str = nil
    
    if type(spec) == "string"
      -- Named window reference
      window = times[spec]
      unless window
        return {
          capabilities: { worker: true, nft: false, nft_dynamic: false }
          eval: (req) -> false, "Time window '#{spec}' not defined"
        }
      start_s, end_s = window[1], window[2]
      desc_str = "'#{spec}'"
    elseif type(spec) == "table"
      -- Inline specification
      start_s = spec.start
      end_s = spec.end
      days = spec.days
      
      unless start_s and end_s
        return {
          capabilities: { worker: true, nft: false, nft_dynamic: false }
          eval: (req) -> false, "Inline time spec requires 'start' and 'end'"
        }
      
      day_bitmask = build_day_bitmask days
      unless day_bitmask
        return {
          capabilities: { worker: true, nft: false, nft_dynamic: false }
          eval: (req) -> false, "Invalid day names in inline time spec"
        }
      
      day_desc = if days
        table.concat days, ","
      else
        "daily"
      desc_str = "#{start_s}–#{end_s} (#{day_desc})"
    else
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "Time window spec must be string or table"
      }

    start_parsed = parse_time_str start_s
    end_parsed = parse_time_str end_s
    unless start_parsed and end_parsed
      return {
        capabilities: { worker: true, nft: false, nft_dynamic: false }
        eval: (req) -> false, "Invalid time window format (expected HH:MM)"
      }

    {
      capabilities: { worker: true, nft: false, nft_dynamic: false }
      start_parsed: start_parsed
      end_parsed: end_parsed
      day_bitmask: day_bitmask
      desc_str: desc_str
      eval: (req) ->
        ts = req.ts or os.time!
        t = os.date "*t", ts
        year, month, day = t.year, t.month, t.day
        wday = t.wday  -- 1=Sunday, 2=Monday, ..., 7=Saturday

        -- Check day-of-week if constraint was specified
        if day_bitmask
          unless bit.band(day_bitmask, bit.lshift(1, wday - 1)) > 0
            return false, "Outside time window #{desc_str} (not a matching day)"

        _start = os.time { :year, :month, :day, hour: start_parsed.hour, min: start_parsed.min, sec: 0 }
        _end   = os.time { :year, :month, :day, hour: end_parsed.hour, min: end_parsed.min, sec: 0 }

        if _start < ts and ts < _end
          true, "In time window #{desc_str}"
        else
          false, "Outside time window #{desc_str}"
    }

{ schema: _schema, factory: _factory }
