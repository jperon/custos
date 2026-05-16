-- src/filter/conditions/in_times.moon
-- Condition : la requête arrive dans au moins une des fenêtres horaires listées.
-- API enrichie : worker-only (basé sur in_time).

--- @tparam table cfg Configuration
-- @treturn function factory (names) → enriched_condition
(cfg) ->
  in_time_factory = require "filter.conditions.in_time"
  (names) ->
    window_names = names
    unless type(names) == "table"
      window_names = { names }
    
    time_conds = {}
    for _, name in ipairs window_names
      time_conds[#time_conds + 1] = in_time_factory(cfg)(name)
      
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      window_names: window_names
      eval: (req) ->
        for _, time_cond in ipairs time_conds
          ok, msg = time_cond.eval req
          return ok, msg if ok
        false, "Not in any time window: #{table.concat window_names, ', '}"
    }
