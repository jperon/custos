-- src/filter/conditions/from_user.moon
-- Condition : squelette — authentification utilisateur non implémentée.
-- Retourne toujours false pour l'instant.
-- L'architecture (cfg)(user)(req) est compatible avec une implémentation
-- future (mécanisme à définir — pas nécessairement websocket).

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (user: string) → (req) → bool, reason
(cfg) -> (user) ->
  --- @tparam table req {src_ip: string, ...}
  -- @treturn boolean, string
  (req) ->
    false, "from_user not implemented (user=#{user})"
