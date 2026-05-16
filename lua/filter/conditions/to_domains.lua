return function(cfg)
  local to_domain_factory = require("filter.conditions.to_domain")
  return function(domains)
    local domain_list = domains
    if not (type(domains) == "table") then
      domain_list = {
        domains
      }
    end
    local domain_conds = { }
    for _, d in ipairs(domain_list) do
      domain_conds[#domain_conds + 1] = to_domain_factory(cfg)(d)
    end
    return {
      capabilities = {
        worker = true,
        nft = false,
        nft_dynamic = false
      },
      domains = domain_list,
      eval = function(req)
        for _, domain_cond in ipairs(domain_conds) do
          local ok, msg = domain_cond.eval(req)
          if ok then
            return ok, msg
          end
        end
        return false, "Not matched by any domain"
      end,
      creates_dynamic_scope = true
    }
  end
end
