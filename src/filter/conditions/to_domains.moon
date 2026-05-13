-- src/filter/conditions/to_domains.moon
-- Condition : le domaine demandé correspond à l'un des domaines listés.
-- API enrichie : worker-only (DNS matching).

--- @tparam table cfg Configuration
-- @treturn function factory (domains) → enriched_condition
(cfg) ->
  (domains) ->
    domain_list = domains
    unless type(domains) == "table"
      domain_list = { domains }
    
    {
      capabilities: { worker: true, nft_static: false, nft_dynamic: false }
      domains: domain_list
      eval: (req) ->
        to_domain_factory = require "filter.conditions.to_domain"
        for _, d in ipairs domain_list
          domain_cond = to_domain_factory(cfg)(d)
          ok, msg = domain_cond.eval req
          return ok, msg if ok
        false, "Not matched by any domain"
      creates_dynamic_scope: true
    }
