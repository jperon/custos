-- src/filter/conditions/to_domains.moon
-- Condition : le domaine demandé correspond à l'un des domaines listés.
-- API enrichie : worker-only (DNS matching).

--- @tparam table cfg Configuration
-- @treturn function factory (domains) → enriched_condition
(cfg) ->
  to_domain_factory = require "filter.conditions.to_domain"
  (domains) ->
    domain_list = domains
    unless type(domains) == "table"
      domain_list = { domains }
    
    domain_conds = {}
    for _, d in ipairs domain_list
      domain_conds[#domain_conds + 1] = to_domain_factory(cfg)(d)
    
    {
      capabilities: { worker: true, nft: false, nft_dynamic: false }
      domains: domain_list
      eval: (req) ->
        for _, domain_cond in ipairs domain_conds
          ok, msg = domain_cond.eval req
          return ok, msg if ok
        false, "Not matched by any domain"
      creates_dynamic_scope: true
    }
