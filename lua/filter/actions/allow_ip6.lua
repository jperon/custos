return function(cfg)
  return function(rule)
    return {
      capabilities = {
        worker = true,
        nft = false
      },
      eval = function(req)
        return "allow_ip6", "Allow IPv6 only by rule: " .. tostring(rule.description or '?')
      end,
      compile_nft = function() end,
      verdict = function()
        return "allow_ip6"
      end
    }
  end
end
