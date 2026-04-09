-- src/filter/conditions/to_domains.moon
-- Condition : le domaine demandé correspond à l'un des domaines listés.
-- Port direct de shelterfilter conditions/to_domains.moon.
-- Essaie chaque domaine de la liste jusqu'à trouver une correspondance.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (domains: table) → (req) → bool, reason
(cfg) -> (domains) ->
  _to_domain = require "filter.conditions.to_domain"
  checkers   = [(_to_domain cfg)(d) for d in *domains]

  --- @tparam table req {domain: string, ...}
  -- @treturn boolean, string
  (req) ->
    for _, c in ipairs checkers
      ok, msg = c req
      return ok, msg if ok
    false, "Not matched by any domain"
