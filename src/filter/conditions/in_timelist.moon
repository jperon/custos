-- src/filter/conditions/in_timelist.moon
-- Condition : la requête arrive dans l'un des créneaux horaires d'une liste nommée.
-- API enrichie : worker-only (basé sur in_time).
-- cfg.times_lists[name] = { "window1", "window2", ... }

--- @tparam table cfg Configuration
-- @treturn function factory (list_name) → enriched_condition
(cfg) ->
  (list_name) ->
    time_lists = cfg.times_lists or {}
    window_names = time_lists[list_name]
    unless window_names
      return {
        capabilities: { worker: true, nft_static: false, nft_dynamic: false }
        eval: (req) -> false, "Time list '#{list_name}' not defined"
      }

    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      list_name: list_name
      window_names: window_names
      eval: (req) ->
        -- DRY: delegate to in_time for each window
        in_time_factory = require "filter.conditions.in_time"
        for _, name in ipairs window_names
          window_cond = in_time_factory(cfg)(name)
          ok, reason = window_cond.eval req
          return true, reason if ok
        false, "Outside all windows in list '#{list_name}'"
    }
