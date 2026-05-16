-- src/filter/conditions/in_timelists.moon
-- Condition : la requête arrive dans l'un des créneaux de plusieurs listes nommées.
-- API enrichie : worker-only (basé sur in_time).

--- @tparam table cfg Configuration
-- @treturn function factory (list_names) → enriched_condition
(cfg) ->
  in_timelist_factory = require "filter.conditions.in_timelist"
  (list_names) ->
    lists = list_names
    unless type(list_names) == "table"
      lists = { list_names }
    
    list_conds = {}
    for _, name in ipairs lists
      list_conds[#list_conds + 1] = in_timelist_factory(cfg)(name)
      
    {
      capabilities: { worker: true, nft: false, nft_dynamic: false }
      lists: lists
      eval: (req) ->
        for _, list_cond in ipairs list_conds
          ok, reason = list_cond.eval req
          return true, reason if ok
        false, "Outside all windows in specified lists"
    }
