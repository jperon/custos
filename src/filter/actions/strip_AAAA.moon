-- src/filter/actions/strip_AAAA.moon
-- Action : enlever les enregistrements AAAA de la réponse DNS.
-- Seule : pas d'injection nft (skip_nft=true, explicit_allow non défini).
-- Combinée avec "allow" : allow.on_response pose explicit_allow=true, l'injection a lieu.

{ :strip_dns_rr, :add_ede_modified, :clear_ad_bit } = require "dns_ede"
(require "ipc").register_modifier "strip_aaaa"

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
(cfg) ->
  (rule) ->
    {
      capabilities: { worker: true, nft: false }
      eval: (req) ->
        true, "Strip AAAA by rule: #{rule.description or '?'}"
      on_response: (ctx) ->
        stripped = strip_dns_rr ctx.dns_raw, "AAAA"
        if stripped != ctx.dns_raw
          stripped = add_ede_modified(stripped, ctx.reason) or stripped
          ctx.dns_raw  = clear_ad_bit stripped
          ctx.modified = true
        ctx.skip_nft     = true
        ctx.action_label = "response_strip_aaaa"
      compile_nft: ->
      verdict: ->
        "accept"
    }
