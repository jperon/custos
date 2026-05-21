local _schema = {
  label = "Autoriser",
  description = "Autorise la requête DNS et injecte les IPs dans nftables",
  arg_type = nil
}
local _factory
_factory = function(cfg)
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
return {
  schema = _schema,
  factory = _factory
}
