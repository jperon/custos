-- src/filter/conditions/in_timelist.moon
-- Condition : la requête arrive dans l'un des créneaux horaires d'une liste nommée.
-- cfg.times_lists[name] = { "window1", "window2", ... }
--- @tparam table cfg Configuration du filtre
-- @treturn function factory (list_name: string) → (req) → bool, reason
(cfg) -> (list_name) ->
  time_lists = cfg.times_lists or {}
  window_names = time_lists[list_name]
  unless window_names
    return (req) -> false, "Time list '#{list_name}' not defined"

  -- Pré-charger les factories de fenêtres individuelles
  in_time_factory = require "filter.conditions.in_time"
  windows = {}
  for _, name in ipairs window_names
    windows[#windows + 1] = in_time_factory cfg name

  --- @tparam table req {ts: number, ...}
  -- @treturn boolean, string
  (req) ->
    for _, window_fn in ipairs windows
      ok, reason = window_fn req
      return true, reason if ok
    false, "Outside all windows in list '#{list_name}'"
