return function(cfg)
  return function(rule)
    return {
      capabilities = {
        worker = true,
        nft = true
      },
      eval = function(req)
        return false, "Denied by rule: " .. tostring(rule.description or '?')
      end,
      compile_nft = function()
        return "drop", nil
      end,
      verdict = function()
        return "drop"
      end
    }
  end
end
