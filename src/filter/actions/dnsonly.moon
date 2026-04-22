-- src/filter/actions/dnsonly.moon
-- Action : autoriser la résolution DNS mais ne pas ajouter les IPs dans
-- les sets nft (les redirections HTTP/80 restent actives — captive portal).
--
-- Retourne "dnsonly" (valeur truthy distincte de `true`).
-- Le worker Q0 la traite via write_dnsonly_msg ; Q1 patche le TTL + EDE
-- mais n'injecte aucune entrée dans mac4_allowed / mac6_allowed / ip4/ip6.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → (req) → string|boolean, string
(cfg) ->
  (rule) ->
    --- @tparam table req
    -- @treturn string|boolean, string
    (req) -> "dnsonly", "DNS only (no nft) by rule: #{rule.description or '?'}"
