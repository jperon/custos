local strip_aaaa_rr, add_ede_modified, clear_ad_bit
do
  local _obj_0 = require("dns_ede")
  strip_aaaa_rr, add_ede_modified, clear_ad_bit = _obj_0.strip_aaaa_rr, _obj_0.add_ede_modified, _obj_0.clear_ad_bit
end
return function(cfg)
  return function(rule)
    return {
      capabilities = {
        worker = true,
        nft = false
      },
      eval = function(req)
        return true, "Strip AAAA by rule: " .. tostring(rule.description or '?')
      end,
      on_response = function(ctx)
        local stripped = strip_aaaa_rr(ctx.dns_raw)
        if stripped ~= ctx.dns_raw then
          stripped = add_ede_modified(stripped, ctx.reason) or stripped
          ctx.dns_raw = clear_ad_bit(stripped)
          ctx.modified = true
        end
        ctx.skip_nft = true
        ctx.action_label = "response_strip_aaaa"
      end,
      compile_nft = function() end,
      verdict = function()
        return "accept"
      end
    }
  end
end
