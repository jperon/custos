return function(cfg)
  return function(domain)
    if domain == "_any" then
      return function(req)
        return req.domain ~= nil, "domain available"
      end
    end
    if domain == "_none" then
      return function(req)
        return req.domain == nil, "domain not available"
      end
    end
    return function(req)
      local _domain = req.domain
      if not (_domain) then
        return false, "Domain not in request"
      end
      if _domain == domain then
        return true, "Exact match"
      end
      local pos = _domain:find(".", 1, true)
      while pos do
        local suffix = _domain:sub(pos + 1)
        if suffix == domain then
          return true, "Subdomain matched"
        end
        pos = _domain:find(".", pos + 1, true)
      end
      return false, "Domain not matched"
    end
  end
end
