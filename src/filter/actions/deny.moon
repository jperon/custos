-- src/filter/actions/deny.moon
-- Action : bloquer la requête.
-- API enrichie : support worker + nft.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
_schema = {
  label:       "Bloquer"
  description: "Bloque la requête DNS (réponse REFUSED)"
  arg_type:    nil
}

_factory = (cfg) ->
  (rule) ->
    {
      capabilities: { worker: true, nft: true }
      eval: (req) ->
        false, "Denied by rule: #{rule.description or '?'}"
      compile_nft: ->
        "drop", nil
      verdict: ->
        "drop"
    }

{ schema: _schema, factory: _factory }
