-- src/filter/conditions/in_timelists.moon
-- Condition : la requête arrive dans l'un des créneaux de plusieurs listes nommées.
-- API enrichie : worker-only (basé sur in_time).

--- @tparam table cfg Configuration
-- @treturn function factory (list_names) → enriched_condition
(cfg) ->
  (list_names) ->
    lists = list_names
    unless type(list_names) == "table"
      lists = { list_names }
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      lists: lists
      eval: (req) ->
        in_timelist_factory = require "filter.conditions.in_timelist"
        for _, name in ipairs lists
          list_cond = in_timelist_factory(cfg)(name)
          ok, reason = list_cond.eval req
          return true, reason if ok
        false, "Outside all windows in specified lists"
    }
