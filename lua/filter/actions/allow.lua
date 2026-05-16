return function(cfg)
  return function(rule)
    return {
      capabilities = {
        worker = true,
        nft = true
      },
      eval = function(req)
        return true, "Allowed by rule: " .. tostring(rule.description or '?')
      end,
      compile_nft = function()
        return "accept", nil
      end,
      verdict = function()
        return "accept"
      end
    }
  end
end
