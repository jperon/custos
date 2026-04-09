-- src/filter/conditions/to_domainlists.moon
-- Condition : le domaine appartient à au moins une des listes nommées.
-- Port de shelterfilter conditions/to_domainlists.moon.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (listnames: table) → (req) → bool, reason
(cfg) -> (listnames) ->
  _to_domainlist = require "filter.conditions.to_domainlist"
  checkers = [(_to_domainlist cfg)(name) for name in *listnames]

  --- @tparam table req {domain: string, ...}
  -- @treturn boolean, string
  (req) ->
    for _, c in ipairs checkers
      ok, msg = c req
      return ok, msg if ok
    false, "Domain not in any of: #{table.concat listnames, ', '}"
