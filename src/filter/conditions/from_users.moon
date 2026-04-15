-- src/filter/conditions/from_users.moon
-- Condition : l'IP source a une session active pour l'un des utilisateurs listés.
-- Analogue de from_nets / from_macs pour les utilisateurs.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (users: table) → (req) → bool, reason
(cfg) -> (users) ->
  _from_user = require "filter.conditions.from_user"
  checkers  = [(_from_user cfg)(user) for user in *users]

  --- @tparam table req {src_ip: string, ...}
  -- @treturn boolean, string
  (req) ->
    for _, c in ipairs checkers
      ok, msg = c req
      return ok, msg if ok
    false, "Not matched by any user"
