local _update_0 = "ipc"
package.loaded[_update_0] = package.loaded[_update_0] or {
  register_modifier = function()
    return nil
  end
}
local _dns_ede_stub
_dns_ede_stub = {
  strip_dns_rr = function(raw, rtype)
    if rtype == "A" or rtype == "AAAA" then
      return raw .. "_stripped"
    else
      return raw
    end
  end,
  add_ede_modified = function(raw, reason)
    return raw .. "_ede"
  end,
  clear_ad_bit = function(raw)
    return raw .. "_noad"
  end
}
package.loaded["dns_ede"] = _dns_ede_stub
describe("filter.actions.dns_strip", function()
  local dns_strip_factory = (require("filter.actions.dns_strip")).factory
  local cfg = {
    nft = {
      ip_timeout = "2m"
    }
  }
  it("strip A : eval retourne true", function()
    local rule = {
      description = "Strip A rule",
      dns_strip = {
        rr_type = "A"
      }
    }
    local action = (dns_strip_factory(cfg))(rule)
    local v, msg = action.eval({ })
    assert.is_true(v)
    assert.is_not_nil(msg)
    return assert.match("Strip A", msg)
  end)
  it("strip AAAA : eval retourne true", function()
    local rule = {
      description = "Strip AAAA rule",
      dns_strip = {
        rr_type = "AAAA"
      }
    }
    local action = (dns_strip_factory(cfg))(rule)
    local v, msg = action.eval({ })
    assert.is_true(v)
    return assert.match("Strip AAAA", msg)
  end)
  it("rr_type par défaut = A", function()
    local rule = {
      description = "Default rule"
    }
    local action = (dns_strip_factory(cfg))(rule)
    local v, msg = action.eval({ })
    assert.is_true(v)
    return assert.match("Strip A", msg)
  end)
  it("compile_nft retourne nil (pas de support nft)", function()
    local rule_cfg = {
      dns_strip = {
        rr_type = "A"
      }
    }
    local rule = {
      description = "Strip rule"
    }
    local action = (dns_strip_factory(cfg, rule_cfg))(rule)
    local stmt = action.compile_nft()
    return assert.is_nil(stmt)
  end)
  it("verdict retourne 'accept'", function()
    local rule_cfg = {
      dns_strip = {
        rr_type = "A"
      }
    }
    local rule = {
      description = "Strip rule"
    }
    local action = (dns_strip_factory(cfg, rule_cfg))(rule)
    return assert.equals("accept", action.verdict())
  end)
  it("capabilities : worker=true, nft=false", function()
    local rule = {
      description = "Strip rule",
      dns_strip = {
        rr_type = "A"
      }
    }
    local action = (dns_strip_factory(cfg))(rule)
    assert.is_true(action.capabilities.worker)
    return assert.is_false(action.capabilities.nft)
  end)
  it("on_response strip A : strip les enregistrements et marque skip_nft", function()
    local rule = {
      description = "Strip A rule",
      dns_strip = {
        rr_type = "A"
      }
    }
    local action = (dns_strip_factory(cfg))(rule)
    local ctx = {
      dns_raw = "original_dns",
      modified = false,
      skip_nft = false
    }
    action.on_response(ctx)
    assert.is_true(ctx.skip_nft)
    assert.is_true(ctx.modified)
    return assert.equals("response_strip_A", ctx.action_label)
  end)
  it("on_response strip AAAA : strip les enregistrements et marque skip_nft", function()
    local rule = {
      description = "Strip AAAA rule",
      dns_strip = {
        rr_type = "AAAA"
      }
    }
    local action = (dns_strip_factory(cfg))(rule)
    local ctx = {
      dns_raw = "original_dns",
      modified = false,
      skip_nft = false
    }
    action.on_response(ctx)
    assert.is_true(ctx.skip_nft)
    assert.is_true(ctx.modified)
    return assert.equals("response_strip_AAAA", ctx.action_label)
  end)
  return it("on_response : pas de modification si strip ne change rien", function()
    local rule = {
      description = "Strip A rule",
      dns_strip = {
        rr_type = "A"
      }
    }
    local old_stub = package.loaded["dns_ede"]
    package.loaded["dns_ede"] = nil
    package.loaded["filter.actions.dns_strip"] = nil
    package.loaded["dns_ede"] = {
      strip_dns_rr = function(raw, _t)
        return raw
      end,
      add_ede_modified = function(raw, _r)
        return raw
      end,
      clear_ad_bit = function(raw)
        return raw
      end
    }
    local local_factory = (require("filter.actions.dns_strip")).factory
    local local_action = (local_factory(cfg))(rule)
    local ctx = {
      dns_raw = "original_dns",
      modified = false,
      skip_nft = false
    }
    local_action.on_response(ctx)
    assert.is_true(ctx.skip_nft)
    assert.is_false(ctx.modified)
    package.loaded["filter.actions.dns_strip"] = nil
    package.loaded["dns_ede"] = old_stub
  end)
end)
return describe("filter.actions.mail", function()
  local mail_factory = require("filter.actions.mail")
  local cfg = {
    nft = {
      ip_timeout = "2m"
    }
  }
  local rule = {
    description = "Mail rule"
  }
  local action = (mail_factory(cfg))(rule)
  return it("retourne nil comme verdict (effet de bord pur)", function()
    local v, msg = action({ })
    assert.is_nil(v)
    return assert.is_not_nil(msg)
  end)
end)
