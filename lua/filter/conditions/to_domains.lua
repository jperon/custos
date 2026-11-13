local _schema = {
  label = "Domaines cibles",
  description = "Domaine correspondant à l'un des domaines de la liste",
  category = "destination",
  arg_type = "string_list"
}
local _factory
_factory = function(cfg)
  local to_domain_factory = (require("filter.conditions.to_domain")).factory
  return function(domains)
    local domain_list = domains
    if not (type(domains) == "table") then
      domain_list = {
        domains
      }
    end
    local domain_set = { }
    local special_conds = { }
    for _, d in ipairs(domain_list) do
      if d == "_any" or d == "_none" then
        special_conds[#special_conds + 1] = to_domain_factory(cfg)(d)
      else
        domain_set[d] = true
      end
    end
    return {
      capabilities = {
        worker = true,
        nft = false,
        nft_dynamic = false
      },
      domains = domain_list,
      eval = function(req)
        for _, special in ipairs(special_conds) do
          local ok, msg = special.eval(req)
          if ok then
            return ok, msg
          end
        end
        local _domain = req.domain
        if not (_domain) then
          return false, "Not matched by any domain"
        end
        if domain_set[_domain] then
          return true, "Exact match"
        end
        local pos = _domain:find(".", 1, true)
        while pos do
          if domain_set[_domain:sub(pos + 1)] then
            return true, "Subdomain matched"
          end
          pos = _domain:find(".", pos + 1, true)
        end
        return false, "Not matched by any domain"
      end,
      creates_dynamic_scope = true
    }
  end
end
return {
  schema = _schema,
  factory = _factory
}
