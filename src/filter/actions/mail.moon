-- src/filter/actions/mail.moon
-- Action : notification par e-mail — squelette (non implémenté).
-- L'architecture (cfg)(rule)(req) est compatible avec une implémentation
-- future basée sur un MTA ou une API SMTP.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → (req) → boolean, string
(cfg) -> (rule) ->
  --- @tparam table req
  -- @treturn boolean, string
  (req) -> nil, "mail action not implemented"
