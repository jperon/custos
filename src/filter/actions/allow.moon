-- src/filter/actions/allow.moon
-- Action : autoriser la requête.
-- API enrichie : support worker + nft.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
(cfg) ->
  (rule) ->
    {
      capabilities: { worker: true, nft: true }
      eval: (req) ->
        true, "Allowed by rule: #{rule.description or '?'}"
      compile_nft: ->
        "accept", nil
      verdict: ->
        "accept"
    }
