(require("ipc")).register_modifier("dnsonly")
local _schema = {
  label = "DNS seulement",
  description = "Résolution DNS autorisée, sans injection dans nftables",
  arg_type = nil
}
local _factory
_factory = function(cfg)
  return function(rule)
    return {
      capabilities = {
        worker = true,
        nft = false
      },
      eval = function(req)
        return true, "DNS only (no nft) by rule: " .. tostring(rule.description or '?')
      end,
      on_response = function(ctx)
        ctx.skip_nft = true
        ctx.action_label = "response_dnsonly"
      end,
      compile_nft = function() end,
      verdict = function()
        return "dnsonly"
      end
    }
  end
end
return {
  schema = _schema,
  factory = _factory
}
