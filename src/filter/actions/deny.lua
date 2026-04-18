return function(cfg)
  return function(rule)
    return function(req)
      return false, "Denied by rule: " .. tostring(rule.description or '?')
    end
  end
end
