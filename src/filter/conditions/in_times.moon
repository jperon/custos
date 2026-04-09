-- src/filter/conditions/in_times.moon
-- Condition : la requête arrive dans au moins une des fenêtres horaires listées.
-- Port de shelterfilter (pattern analogue à to_domains/to_domainlists).

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (names: table) → (req) → bool, reason
(cfg) -> (names) ->
  _in_time = require "filter.conditions.in_time"
  checkers = [(_in_time cfg)(name) for name in *names]

  --- @tparam table req {ts: number, ...}
  -- @treturn boolean, string
  (req) ->
    for _, c in ipairs checkers
      ok, msg = c req
      return ok, msg if ok
    false, "Not in any time window: #{table.concat names, ', '}"
