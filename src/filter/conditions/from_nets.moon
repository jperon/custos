-- src/filter/conditions/from_nets.moon
-- Condition : l'IP source appartient à l'un des CIDRs listés inline.
-- Analogue de to_domains pour les réseaux.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (cidrs: table) → (req) → bool, reason
(cfg) -> (cidrs) ->
  _from_net = require "filter.conditions.from_net"
  checkers  = [(_from_net cfg)(cidr) for cidr in *cidrs]

  --- @tparam table req {src_ip: string, ...}
  -- @treturn boolean, string
  (req) ->
    for _, c in ipairs checkers
      ok, msg = c req
      return ok, msg if ok
    false, "Not matched by any CIDR"
