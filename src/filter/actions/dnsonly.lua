return function(cfg)
  return function(rule)
    return function(req)
      return "dnsonly", "DNS only (no nft) by rule: " .. tostring(rule.description or '?')
    end
  end
end
