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
      on_response = function(ctx)
        ctx.explicit_allow = true
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
