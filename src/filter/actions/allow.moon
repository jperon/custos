-- src/filter/actions/allow.moon
-- Action : autoriser la requête.
-- Port direct de shelterfilter actions/allow.moon.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → (req) → boolean, string
(cfg) -> (rule) ->
  --- @tparam table req
  -- @treturn boolean, string
  (req) -> true, "Allowed by rule: #{rule.description or '?'}"
