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
describe("filter.actions.strip_A", function()
  local strip_A_factory = require("filter.actions.strip_A")
  local cfg = {
    nft = {
      ip_timeout = "2m"
    }
  }
  local rule = {
    description = "Strip A rule"
  }
  local action = (strip_A_factory(cfg))(rule)
  it("eval retourne true (verdict allow)", function()
    local v, msg = action.eval({ })
    assert.is_true(v)
    return assert.is_not_nil(msg)
  end)
  it("compile_nft retourne nil (pas de support nft)", function()
    local stmt = action.compile_nft()
    return assert.is_nil(stmt)
  end)
  it("verdict retourne 'accept'", function()
    return assert.equals("accept", action.verdict())
  end)
  it("capabilities : worker=true, nft=false", function()
    assert.is_true(action.capabilities.worker)
    return assert.is_false(action.capabilities.nft)
  end)
  it("on_response : strip les enregistrements A et marque skip_nft", function()
    local ctx = {
      dns_raw = "original_dns",
      modified = false,
      skip_nft = false
    }
    action.on_response(ctx)
    assert.is_true(ctx.skip_nft)
    assert.is_true(ctx.modified)
    return assert.equals("response_strip_a", ctx.action_label)
  end)
  return it("on_response : pas de modification si strip ne change rien", function()
    local old_stub = package.loaded["dns_ede"]
    package.loaded["dns_ede"] = nil
    package.loaded["filter.actions.strip_A"] = nil
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
    local local_factory = require("filter.actions.strip_A")
    local local_action = (local_factory(cfg))(rule)
    local ctx = {
      dns_raw = "original_dns",
      modified = false,
      skip_nft = false
    }
    local_action.on_response(ctx)
    assert.is_true(ctx.skip_nft)
    assert.is_false(ctx.modified)
    package.loaded["filter.actions.strip_A"] = nil
    package.loaded["dns_ede"] = old_stub
  end)
end)
describe("filter.actions.strip_AAAA", function()
  package.loaded["filter.actions.strip_AAAA"] = nil
  local strip_AAAA_factory = require("filter.actions.strip_AAAA")
  local cfg = {
    nft = {
      ip_timeout = "2m"
    }
  }
  local rule = {
    description = "Strip AAAA rule"
  }
  local action = (strip_AAAA_factory(cfg))(rule)
  it("eval retourne true", function()
    local v, _ = action.eval({ })
    return assert.is_true(v)
  end)
  it("compile_nft retourne nil", function()
    return assert.is_nil(action.compile_nft())
  end)
  it("verdict retourne 'accept'", function()
    return assert.equals("accept", action.verdict())
  end)
  it("capabilities : worker=true, nft=false", function()
    assert.is_true(action.capabilities.worker)
    return assert.is_false(action.capabilities.nft)
  end)
  return it("on_response : strip les AAAA et marque skip_nft + modified", function()
    local ctx = {
      dns_raw = "original_dns",
      modified = false,
      skip_nft = false
    }
    action.on_response(ctx)
    assert.is_true(ctx.skip_nft)
    assert.is_true(ctx.modified)
    return assert.equals("response_strip_aaaa", ctx.action_label)
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
