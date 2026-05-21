describe("filter.conditions.not", function()
  local not_factory = (require("filter.conditions.not")).factory
  local cfg = {
    nft = {
      ip_timeout = "2m"
    }
  }
  describe("eval (worker)", function()
    it("négation d'une condition matchée → false", function()
      local cond = (not_factory(cfg))({
        from_vlan = 1
      })
      local ok, msg = cond.eval({
        vlan = 1
      })
      assert.is_false(ok)
      return assert.is_not_nil(msg:find("negated to false"))
    end)
    it("négation d'une condition non-matchée → true", function()
      local cond = (not_factory(cfg))({
        from_vlan = 1
      })
      local ok, msg = cond.eval({
        vlan = 2
      })
      assert.is_true(ok)
      return assert.is_not_nil(msg:find("negated to true"))
    end)
    return it("nil pass-through : inner retourne nil → not retourne nil", function()
      package.loaded["filter.conditions.always_nil"] = function(cfg_inner)
        return function(_args)
          local _ = {
            capabilities = {
              worker = true,
              nft = false,
              nft_dynamic = false
            }
          }
          return {
            eval = function(req)
              return nil, "indeterminate"
            end
          }
        end
      end
      local cond = (not_factory(cfg))({
        always_nil = true
      })
      local ok, msg = cond.eval({ })
      assert.is_nil(ok)
      assert.equals("indeterminate", msg)
      package.loaded["filter.conditions.always_nil"] = nil
    end)
  end)
  describe("capabilities et métadonnées", function()
    it("negate_mark est true", function()
      local cond = (not_factory(cfg))({
        from_vlan = 1
      })
      return assert.is_true(cond.negate_mark)
    end)
    it("capabilities.nft hérite de la sous-condition nft-capable", function()
      local cond = (not_factory(cfg))({
        from_vlan = 1
      })
      return assert.is_true(cond.capabilities.nft)
    end)
    it("capabilities.nft false si sous-condition worker-only", function()
      local cond = (not_factory(cfg))({
        in_time = "08:00-18:00"
      })
      return assert.is_false(cond.capabilities.nft)
    end)
    it("capabilities.worker est toujours true", function()
      local cond = (not_factory(cfg))({
        from_vlan = 1
      })
      return assert.is_true(cond.capabilities.worker)
    end)
    it("hérite creates_dynamic_scope si sous-condition le déclare", function()
      local cond = (not_factory(cfg))({
        to_domain = "example.com"
      })
      return assert.is_true(cond.creates_dynamic_scope)
    end)
    it("creates_dynamic_scope false si sous-condition ne le déclare pas", function()
      local cond = (not_factory(cfg))({
        from_vlan = 1
      })
      return assert.is_false(cond.creates_dynamic_scope)
    end)
    return it("compile_nft délègue à la sous-condition", function()
      local cond = (not_factory(cfg))({
        from_vlan = 1
      })
      assert.is_function(cond.compile_nft)
      local expr, err = cond.compile_nft("ip")
      assert.is_nil(err)
      return assert.is_not_nil(expr:find("vlan", 1, true))
    end)
  end)
  return describe("erreurs de configuration", function()
    it("argument non-table → eval retourne false avec message d'erreur", function()
      local cond = (not_factory(cfg))("pas_une_table")
      local ok, msg = cond.eval({ })
      assert.is_false(ok)
      return assert.is_not_nil(msg:find("requires"))
    end)
    return it("table vide → eval retourne false avec message d'erreur", function()
      local cond = (not_factory(cfg))({ })
      local ok, msg = cond.eval({ })
      assert.is_false(ok)
      return assert.is_not_nil(msg:find("empty"))
    end)
  end)
end)
return describe("filter.nft_compiler avec condition not", function()
  local compiler = require("filter.nft_compiler")
  local rule_mod = require("filter.rule")
  it("génère le pattern deux règles (escape + fallback) pour not: { from_vlan }", function()
    local cfg = {
      nft = {
        ip_timeout = "2m"
      },
      rules = {
        {
          rule_id = "test_not_vlan",
          actions = {
            "deny"
          },
          conditions = {
            ["not"] = {
              from_vlan = 42
            }
          }
        }
      }
    }
    local compiled = rule_mod.compile_rules(cfg)
    local plan = compiler.compile(cfg, compiled.rules_metadata)
    local out = compiler.render(plan)
    assert.is_not_nil(out:find("vlan id 42", 1, true))
    assert.is_not_nil(out:find("not-negation", 1, true))
    return assert.is_not_nil(out:find("counter drop", 1, true))
  end)
  return it("génère escape + fallback avec condition normale combinée", function()
    local cfg = {
      nft = {
        ip_timeout = "2m"
      },
      rules = {
        {
          rule_id = "test_not_combined",
          actions = {
            "deny"
          },
          conditions = {
            from_net = "10.0.0.0/8",
            ["not"] = {
              from_vlan = 42
            }
          }
        }
      }
    }
    local compiled = rule_mod.compile_rules(cfg)
    local plan = compiler.compile(cfg, compiled.rules_metadata)
    local out = compiler.render(plan)
    assert.is_not_nil(out:find("ip saddr", 1, true))
    assert.is_not_nil(out:find("vlan id 42", 1, true))
    return assert.is_not_nil(out:find("not-negation", 1, true))
  end)
end)
