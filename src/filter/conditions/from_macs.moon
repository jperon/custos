-- src/filter/conditions/from_macs.moon
-- Condition : l'adresse MAC source correspond à l'une des MACs listées inline.
-- Analogue de to_domains pour les adresses MAC.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (macs: table) → (req) → bool, reason
(cfg) -> (macs) ->
  _from_mac = require "filter.conditions.from_mac"
  checkers  = [(_from_mac cfg)(mac) for mac in *macs]

  --- @tparam table req {mac: string, ...}
  -- @treturn boolean, string
  (req) ->
    for _, c in ipairs checkers
      ok, msg = c req
      return ok, msg if ok
    false, "Not matched by any MAC"
