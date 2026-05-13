-- src/filter/actions/deny.moon
-- Action : bloquer la requête.
-- API enrichie : support worker + nft.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
(cfg) ->
  (rule) ->
    {
      capabilities: { worker: true, nft: true }
      worker_only: false
      eval: (req) ->
        false, "Denied by rule: #{rule.description or '?'}"
      compile_nft: ->
        "drop", nil
      verdict: ->
        "drop"
    }
