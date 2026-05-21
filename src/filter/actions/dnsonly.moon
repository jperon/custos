-- src/filter/actions/dnsonly.moon
-- Action : autoriser la résolution DNS mais ne pas injecter les IPs dans les sets nft.
-- on_response déclare skip_nft=true ; aucune modification du payload DNS.

(require "ipc").register_modifier "dnsonly"

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
_schema = {
  label:       "DNS seulement"
  description: "Résolution DNS autorisée, sans injection dans nftables"
  arg_type:    nil
}

_factory = (cfg) ->
  (rule) ->
    {
      capabilities: { worker: true, nft: false }
      eval: (req) ->
        true, "DNS only (no nft) by rule: #{rule.description or '?'}"
      on_response: (ctx) ->
        ctx.skip_nft       = true
        ctx.action_label   = "response_dnsonly"
      compile_nft: ->
      verdict: ->
        "dnsonly"
    }

{ schema: _schema, factory: _factory }
