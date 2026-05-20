local strip_dns_rr, add_ede_modified, clear_ad_bit
do
  local _obj_0 = require("dns_ede")
  strip_dns_rr, add_ede_modified, clear_ad_bit = _obj_0.strip_dns_rr, _obj_0.add_ede_modified, _obj_0.clear_ad_bit
end
(require("ipc")).register_modifier("dns_strip")
return function(cfg, rule_cfg)
  local rr_type = "A"
  if rule_cfg.dns_strip and rule_cfg.dns_strip.rr_type then
    rr_type = rule_cfg.dns_strip.rr_type
  end
  return function(rule)
    return {
      capabilities = {
        worker = true,
        nft = false
      },
      eval = function(req)
        return true, "Strip " .. tostring(rr_type) .. " by rule: " .. tostring(rule.description or '?')
      end,
      on_response = function(ctx)
        local stripped = strip_dns_rr(ctx.dns_raw, rr_type)
        if stripped ~= ctx.dns_raw then
          stripped = add_ede_modified(stripped, ctx.reason) or stripped
          ctx.dns_raw = clear_ad_bit(stripped)
          ctx.modified = true
        end
        ctx.skip_nft = true
        ctx.action_label = "response_strip_" .. tostring(rr_type)
      end,
      compile_nft = function() end,
      verdict = function()
        return "accept"
      end
    }
  end
end
