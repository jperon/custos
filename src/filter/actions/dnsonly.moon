-- src/filter/actions/dnsonly.moon
-- Action : autoriser la résolution DNS mais ne pas ajouter les IPs dans
-- les sets nft (les redirections HTTP/80 restent actives — captive portal).
-- API enrichie : worker-only (pas de compilation nft possible).
--
-- Retourne "dnsonly" (valeur truthy distincte de `true`).
-- Le worker question la traite via write_dnsonly_msg ; response patche le TTL + EDE
-- mais n'injecte aucune entrée dans les sets par règle.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
(cfg) ->
  (rule) ->
    {
      capabilities: { worker: true, nft: false }
      eval: (req) ->
        "dnsonly", "DNS only (no nft) by rule: #{rule.description or '?'}"
      compile_nft: ->
      verdict: ->
        "dnsonly"
    }
