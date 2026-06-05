-- src/filter/actions/validate.moon
-- Action : soumettre la requête autorisée au résolveur validateur (second avis
-- DNS). Sans cette action, la duplication vers le validateur n'a pas lieu et la
-- réponse est transmise telle quelle.

(require "ipc").register_modifier "validate"

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
_schema = {
  label:       "Valider via résolveur externe"
  description: "Duplique la question DNS vers le résolveur validateur (ex. DNSforFamily) et corrèle les deux réponses"
  arg_type:    nil
}

_factory = (cfg) ->
  (rule) ->
    {
      capabilities: { worker: true, nft: true }
      allow_modifiers: { validate: true }
      eval: (req) ->
        true, "Validated by rule: #{rule.description or '?'}"
      on_response: (ctx) ->
        ctx.explicit_allow = true
      compile_nft: ->
        "accept", nil
      verdict: ->
        "accept"
    }

{ schema: _schema, factory: _factory }
