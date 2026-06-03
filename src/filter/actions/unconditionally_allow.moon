-- src/filter/actions/unconditionally_allow.moon
-- Action : autoriser la requête sans la soumettre au résolveur validateur
-- (second avis DNS). Utile pour les domaines de confiance absolue où la
-- vérification supplémentaire n'apporte rien et ralentirait inutilement.

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
_schema = {
  label:       "Autoriser sans validateur"
  description: "Autorise la requête DNS sans duplication vers le résolveur validateur"
  arg_type:    nil
}

_factory = (cfg) ->
  (rule) ->
    {
      capabilities: { worker: true, nft: true }
      allow_modifiers: { skip_duplicate: true }
      eval: (req) ->
        true, "Unconditionally allowed by rule: #{rule.description or '?'}"
      on_response: (ctx) ->
        ctx.explicit_allow = true
      compile_nft: ->
        "accept", nil
      verdict: ->
        "accept"
    }

{ schema: _schema, factory: _factory }
