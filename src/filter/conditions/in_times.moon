-- src/filter/conditions/in_times.moon
-- Condition : la requête arrive dans au moins une des fenêtres horaires listées.
-- API enrichie : worker-only (basé sur in_time).

--- @tparam table cfg Configuration
-- @treturn function factory (names) → enriched_condition
(cfg) ->
  (names) ->
    window_names = names
    unless type(names) == "table"
      window_names = { names }
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      worker_only: true
      window_names: window_names
      eval: (req) ->
        in_time_factory = require "filter.conditions.in_time"
        for _, name in ipairs window_names
          time_cond = in_time_factory(cfg)(name)
          ok, msg = time_cond.eval req
          return ok, msg if ok
        false, "Not in any time window: #{table.concat window_names, ', '}"
      compile_nft: -> nil, "in_times requires worker (time-based)"
      creates_dynamic_scope: false
    }
