return function(cfg)
  return function(rule)
    return {
      capabilities = {
        worker = true,
        nft = false
      },
      eval = function(req)
        return "dnsonly", "DNS only (no nft) by rule: " .. tostring(rule.description or '?')
      end,
      compile_nft = function() end,
      verdict = function()
        return "dnsonly"
      end
    }
  end
end
