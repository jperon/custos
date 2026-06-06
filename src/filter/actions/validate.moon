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
  arg_type:    "table"
  arg_fields:  { { name: "validate_resolvers", label: "Résolveurs", type: "list", required: false } }
}

_factory = (cfg) ->
  (rule) ->
    -- validate_resolvers : liste d'IPs spécifique à cette règle (v4/v6 mélangés),
    -- ou nil pour utiliser les résolveurs globaux de cfg.second_opinion.resolvers.
    resolvers = rule.validate_resolvers
    {
      capabilities: { worker: true, nft: true }
      allow_modifiers: { validate: resolvers or true }
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
