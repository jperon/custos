-- src/filter/actions/cname.moon
-- Action : réécrit la réponse DNS en un CNAME synthétique vers la cible
-- configurée (`rule.cname`). Générique — utilisée notamment par les règles
-- SafeSearch (google → forcesafesearch.google.com, etc.).
--
-- La requête est autorisée (eval → allow) afin que la réponse upstream emprunte
-- le pipeline on_response (worker_responses ET doh/query). Le callback remplace
-- alors la réponse par un CNAME : le client re-résout la cible (autorisée par
-- ailleurs). Couvre UDP, TCP et DoH sans forge ni IPC (la réinjection via
-- replace_dns_payload gère déjà les deux transports).

{ :build_cname_response } = require "dns_ede"

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
_schema = {
  label:       "Réécriture CNAME"
  description: "Réécrit la réponse en un CNAME vers la cible configurée"
  arg_type:    "string"
  arg_hint:    "ex: forcesafesearch.google.com"
}

_factory = (cfg) ->
  (rule) ->
    target = rule.cname
    {
      capabilities: { worker: true, nft: false }
      eval: (req) ->
        true, "CNAME → #{target} by rule: #{rule.description or '?'}"
      on_response: (ctx) ->
        rewritten = build_cname_response nil, ctx.dns_raw, target, ctx.reason
        if rewritten
          ctx.dns_raw  = rewritten
          ctx.modified = true
        -- Pas d'IP réelle à injecter : la réponse ne contient qu'un CNAME.
        ctx.skip_nft     = true
        ctx.action_label = "response_cname"
      compile_nft: ->
      verdict: ->
        "accept"
    }

{ schema: _schema, factory: _factory }
