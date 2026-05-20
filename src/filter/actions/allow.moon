-- src/filter/actions/allow.moon
-- Action : autoriser la requête et injecter les IPs dans les sets nft.
-- on_response déclare explicit_allow=true : si une autre action a mis skip_nft=true
-- (ex: strip_AAAA seule), allow le supplante et l'injection nft a lieu quand même.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
(cfg) ->
  (rule) ->
    {
      capabilities: { worker: true, nft: true }
      eval: (req) ->
        true, "Allowed by rule: #{rule.description or '?'}"
      on_response: (ctx) ->
        ctx.explicit_allow = true
      compile_nft: ->
        "accept", nil
      verdict: ->
        "accept"
    }
