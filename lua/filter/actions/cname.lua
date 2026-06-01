local build_cname_response
build_cname_response = require("dns_ede").build_cname_response
local _schema = {
  label = "Réécriture CNAME",
  description = "Réécrit la réponse en un CNAME vers la cible configurée",
  arg_type = "string",
  arg_hint = "ex: forcesafesearch.google.com"
}
local _factory
_factory = function(cfg)
  return function(rule)
    local target = rule.cname
    return {
      capabilities = {
        worker = true,
        nft = false
      },
      eval = function(req)
        return true, "CNAME → " .. tostring(target) .. " by rule: " .. tostring(rule.description or '?')
      end,
      on_response = function(ctx)
        local rewritten = build_cname_response(nil, ctx.dns_raw, target, ctx.reason)
        if rewritten then
          ctx.dns_raw = rewritten
          ctx.modified = true
        end
        ctx.skip_nft = true
        ctx.action_label = "response_cname"
      end,
      compile_nft = function() end,
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
