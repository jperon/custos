-- src/filter/actions/dns_strip.moon
-- Action : enlever les enregistrements DNS d'un type donné de la réponse.
-- eval renvoie un verdict nil (effet de bord pur, comme cname) : la règle ne
-- décide pas seule de l'accès, elle laisse l'évaluation continuer jusqu'à la
-- règle qui apporte le vrai verdict (ex: "Utilisateurs"), tout en s'enregistrant
-- quand même dans response_rule_ids pour que son on_response (strip) s'exécute.
-- Seule (aucune autre règle ne matche derrière) : pas d'injection nft
-- (skip_nft=true, explicit_allow non défini) → default deny.
-- Combinée avec "allow" (ou toute règle "allow" qui matche plus loin) :
-- allow.on_response pose explicit_allow=true, l'injection a lieu.
-- Configurable via rule.dns_strip.rr_type (ex: "A", "AAAA", "CNAME", etc.)

{ :strip_dns_rr, :add_ede_modified, :clear_ad_bit } = require "dns_ede"
(require "ipc").register_modifier "dns_strip"

--- @tparam table cfg Configuration du filtre
-- @treturn function factory (rule) → enriched_action
_schema = {
  label:       "Supprimer enregistrement DNS"
  description: "Supprime un type d'enregistrement de la réponse DNS"
  arg_type:    "table"
  arg_fields:  { { name: "rr_type", label: "Type RR", type: "enum",
                   values: {"A","AAAA","CNAME","MX","TXT"}, required: true, default: "A" }
                 { name: "follow_cname", label: "Suivre la chaîne CNAME", type: "bool", default: true } }
}

_factory = (cfg) ->
  (rule) ->
    -- Extraire rr_type de la configuration de la règle, défaut "A" si non spécifié
    rr_type = "A"
    if rule.dns_strip and rule.dns_strip.rr_type
      rr_type = rule.dns_strip.rr_type
    -- Défaut: suivre la chaîne CNAME dès qu'une règle dns_strip est posée.
    -- Opt-out explicite via follow_cname: false (ancien comportement coût-nul).
    follow_cname = not not (rule.dns_strip and rule.dns_strip.follow_cname != false)
    dns_mod = require "ipparse.l7.dns"   -- mémoïsé à la construction (hors hot-path)
    rr_code = dns_mod.types[rr_type]

    {
      capabilities: { worker: true, nft: false }
      eval: (req) ->
        nil, "Strip #{rr_type} by rule: #{rule.description or '?'}"
      on_response: (ctx) ->
        stripped = strip_dns_rr ctx.dns_raw, rr_type
        if stripped != ctx.dns_raw
          stripped = add_ede_modified(stripped, ctx.reason) or stripped
          ctx.dns_raw  = clear_ad_bit stripped
          ctx.modified = true
        ctx.skip_nft     = true
        ctx.action_label = "response_strip_#{rr_type}"
        ctx.chain_strip_rr = rr_code if follow_cname and rr_code
      compile_nft: ->
      verdict: ->
        "accept"
    }

{ schema: _schema, factory: _factory }
