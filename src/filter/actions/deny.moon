-- src/filter/actions/deny.moon
-- Action : bloquer la requête.
-- Port direct de shelterfilter actions/deny.moon.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → (req) → boolean, string
(cfg) -> (rule) ->
  --- @tparam table req
  -- @treturn boolean, string
  (req) -> false, "Denied by rule: #{rule.description or '?'}"
