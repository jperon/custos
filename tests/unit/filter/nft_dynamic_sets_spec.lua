local _update_0 = "ipc"
package.loaded[_update_0] = package.loaded[_update_0] or {
  register_modifier = function()
    return nil
  end
}
return describe("filter.nft_dynamic_sets", function()
  local dyn_sets = require("filter.nft_dynamic_sets")
  local make_plan
  make_plan = function(rule_overrides)
    if rule_overrides == nil then
      rule_overrides = { }
    end
    local rule = {
      set_src4 = rule_overrides.set_src4,
      set_src6 = rule_overrides.set_src6,
      set_subnet4 = rule_overrides.set_subnet4,
      set_subnet6 = rule_overrides.set_subnet6,
      set_ports = rule_overrides.set_ports,
      set_dyn_ip4 = rule_overrides.set_dyn_ip4,
      set_dyn_ip6 = rule_overrides.set_dyn_ip6,
      set_dyn_mac4 = rule_overrides.set_dyn_mac4,
      set_dyn_mac6 = rule_overrides.set_dyn_mac6
    }
    return {
      rules = {
        rule
      }
    }
  end
  describe("create_set_cmd", function()
    it("génère une commande add set de base", function()
      local cmd = dyn_sets.create_set_cmd("bridge", "dns-filter-bridge", "my_set", "ipv4_addr", "")
      assert.is_not_nil(cmd:find("add set bridge dns-filter-bridge my_set", 1, true))
      return assert.is_not_nil(cmd:find("type ipv4_addr", 1, true))
    end)
    it("inclut les flags si non vides", function()
      local cmd = dyn_sets.create_set_cmd("bridge", "dns-filter-bridge", "my_set", "ipv4_addr", "timeout")
      return assert.is_not_nil(cmd:find("flags timeout", 1, true))
    end)
    return it("pas de flags si chaîne vide", function()
      local cmd = dyn_sets.create_set_cmd("bridge", "tbl", "s", "ipv4_addr", "")
      return assert.is_nil(cmd:find("flags", 1, true))
    end)
  end)
  describe("collect_rule_sets", function()
    it("plan vide → aucun set", function()
      local sets = dyn_sets.collect_rule_sets({
        rules = { }
      })
      return assert.equals(0, #sets)
    end)
    it("plan nil → aucun set", function()
      local sets = dyn_sets.collect_rule_sets(nil)
      return assert.equals(0, #sets)
    end)
    it("collecte set_src4 (ipv4_addr interval)", function()
      local plan = make_plan({
        set_src4 = "r_test_src4"
      })
      local sets = dyn_sets.collect_rule_sets(plan)
      local found = false
      for _, s in ipairs(sets) do
        if s.name == "r_test_src4" then
          found = true
          assert.equals("ipv4_addr", s.type)
          assert.equals("interval", s.flags)
        end
      end
      return assert.is_true(found)
    end)
    it("collecte set_src6 (ipv6_addr interval)", function()
      local plan = make_plan({
        set_src6 = "r_test_src6"
      })
      local sets = dyn_sets.collect_rule_sets(plan)
      local found = false
      for _, s in ipairs(sets) do
        if s.name == "r_test_src6" then
          found = true
          assert.equals("ipv6_addr", s.type)
        end
      end
      return assert.is_true(found)
    end)
    it("collecte set_subnet4 (ipv4_addr interval)", function()
      local plan = make_plan({
        set_subnet4 = "r_test_subnet4"
      })
      local sets = dyn_sets.collect_rule_sets(plan)
      local found = false
      for _, s in ipairs(sets) do
        if s.name == "r_test_subnet4" then
          found = true
          assert.equals("ipv4_addr", s.type)
        end
      end
      return assert.is_true(found)
    end)
    it("collecte set_subnet6 (ipv6_addr interval)", function()
      local plan = make_plan({
        set_subnet6 = "r_test_subnet6"
      })
      local sets = dyn_sets.collect_rule_sets(plan)
      local found = false
      for _, s in ipairs(sets) do
        if s.name == "r_test_subnet6" then
          found = true
          assert.equals("ipv6_addr", s.type)
        end
      end
      return assert.is_true(found)
    end)
    it("collecte set_ports (inet_service, pas de flags)", function()
      local plan = make_plan({
        set_ports = "r_test_ports"
      })
      local sets = dyn_sets.collect_rule_sets(plan)
      local found = false
      for _, s in ipairs(sets) do
        if s.name == "r_test_ports" then
          found = true
          assert.equals("inet_service", s.type)
          assert.equals("", s.flags)
        end
      end
      return assert.is_true(found)
    end)
    it("collecte set_dyn_ip4 (ipv4_addr . ipv4_addr timeout)", function()
      local plan = make_plan({
        set_dyn_ip4 = "r_test_dyn_ip4"
      })
      local sets = dyn_sets.collect_rule_sets(plan)
      local found = false
      for _, s in ipairs(sets) do
        if s.name == "r_test_dyn_ip4" then
          found = true
          assert.equals("ipv4_addr . ipv4_addr", s.type)
          assert.equals("timeout", s.flags)
        end
      end
      return assert.is_true(found)
    end)
    it("collecte set_dyn_ip6 (ipv6_addr . ipv6_addr timeout)", function()
      local plan = make_plan({
        set_dyn_ip6 = "r_test_dyn_ip6"
      })
      local sets = dyn_sets.collect_rule_sets(plan)
      local found = false
      for _, s in ipairs(sets) do
        if s.name == "r_test_dyn_ip6" then
          found = true
          assert.equals("ipv6_addr . ipv6_addr", s.type)
        end
      end
      return assert.is_true(found)
    end)
    it("collecte set_dyn_mac4 (ether_addr . ipv4_addr timeout)", function()
      local plan = make_plan({
        set_dyn_mac4 = "r_test_dyn_mac4"
      })
      local sets = dyn_sets.collect_rule_sets(plan)
      local found = false
      for _, s in ipairs(sets) do
        if s.name == "r_test_dyn_mac4" then
          found = true
          assert.equals("ether_addr . ipv4_addr", s.type)
        end
      end
      return assert.is_true(found)
    end)
    it("collecte set_dyn_mac6 (ether_addr . ipv6_addr timeout)", function()
      local plan = make_plan({
        set_dyn_mac6 = "r_test_dyn_mac6"
      })
      local sets = dyn_sets.collect_rule_sets(plan)
      local found = false
      for _, s in ipairs(sets) do
        if s.name == "r_test_dyn_mac6" then
          found = true
          assert.equals("ether_addr . ipv6_addr", s.type)
        end
      end
      return assert.is_true(found)
    end)
    return it("déduplique les sets identiques entre règles", function()
      local plan = {
        rules = {
          {
            set_src4 = "shared_set",
            set_src6 = nil
          },
          {
            set_src4 = "shared_set",
            set_src6 = nil
          }
        }
      }
      local sets = dyn_sets.collect_rule_sets(plan)
      local count = 0
      for _, s in ipairs(sets) do
        if s.name == "shared_set" then
          count = count + 1
        end
      end
      return assert.equals(1, count)
    end)
  end)
  return describe("generate_set_creation_commands", function()
    return it("génère des commandes pour chaque set", function()
      local plan = make_plan({
        set_src4 = "r_test_src4",
        set_dyn_ip4 = "r_test_dyn_ip4"
      })
      local cmds = dyn_sets.generate_set_creation_commands(plan)
      assert.is_true(#cmds >= 2)
      for _, cmd in ipairs(cmds) do
        assert.is_not_nil(cmd:find("add set", 1, true))
      end
    end)
  end)
end)
