return function(cfg)
  return function(rule)
    return function(req)
      return true, "Allowed by rule: " .. tostring(rule.description or '?')
    end
  end
end
