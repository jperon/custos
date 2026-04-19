-- src/filter/conditions/in_timelists.moon
-- Condition : la requête arrive dans l'un des créneaux de plusieurs listes nommées.
-- cfg.times_lists[name] = { "window1", "window2", ... }
--- @tparam table cfg Configuration du filtre
-- @treturn function factory (list_names: table) → (req) → bool, reason
(cfg) -> (list_names) ->
  unless type list_names == "table"
    error "in_timelists requires a table of list names"

  -- DRY : on compose la condition à partir de plusieurs in_timelist
  in_timelist_factory = require "filter.conditions.in_timelist"
  list_fns = {}
  for _, name in ipairs list_names
    list_fns[#list_fns + 1] = in_timelist_factory cfg name

  --- @tparam table req {ts: number, ...}
  -- @treturn boolean, string
  (req) ->
    for _, list_fn in ipairs list_fns
      ok, reason = list_fn req
      return true, reason if ok
    false, "Outside all windows in specified lists"
