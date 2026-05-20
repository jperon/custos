-- src/filter/actions/dns_strip.moon
-- Action : enlever les enregistrements DNS d'un type donné de la réponse.
-- Seule : pas d'injection nft (skip_nft=true, explicit_allow non défini).
-- Combinée avec "allow" : allow.on_response pose explicit_allow=true, l'injection a lieu.
-- Configurable via rule_cfg.dns_strip.rr_type (ex: "A", "AAAA", "CNAME", etc.)

{ :strip_dns_rr, :add_ede_modified, :clear_ad_bit } = require "dns_ede"
(require "ipc").register_modifier "dns_strip"

--- @tparam table cfg Configuration du filtre
--- @treturn function factory (rule) → enriched_action
return (cfg, rule_cfg) ->
  -- Extraire rr_type de la configuration, défaut "HTTPS" si non spécifié
  rr_type = "HTTPS"
  if rule_cfg.dns_strip and rule_cfg.dns_strip.rr_type
    rr_type = rule_cfg.dns_strip.rr_type

  (rule) ->
    {
      capabilities: { worker: true, nft: false }
      eval: (req) ->
        true, "Strip #{rr_type} by rule: #{rule.description or '?'}"
      on_response: (ctx) ->
        stripped = strip_dns_rr ctx.dns_raw, rr_type
        if stripped != ctx.dns_raw
          stripped = add_ede_modified(stripped, ctx.reason) or stripped
          ctx.dns_raw  = clear_ad_bit stripped
          ctx.modified = true
        ctx.skip_nft     = true
        ctx.action_label = "response_strip_#{rr_type}"
      compile_nft: ->
      verdict: ->
        "accept"
    }
