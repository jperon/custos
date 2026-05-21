-- tests/unit/filter/nft_dynamic_sets_spec.moon
-- Busted spec pour filter.nft_dynamic_sets.
-- Charge depuis lua/ pour alimenter luacov.

package.loaded["ipc"] or= { register_modifier: -> nil }

describe "filter.nft_dynamic_sets", ->
  dyn_sets = require "filter.nft_dynamic_sets"

  -- Plan minimal avec tous les types de sets possibles
  make_plan = (rule_overrides={}) ->
    rule = {
      set_src4:    rule_overrides.set_src4
      set_src6:    rule_overrides.set_src6
      set_subnet4: rule_overrides.set_subnet4
      set_subnet6: rule_overrides.set_subnet6
      set_ports:   rule_overrides.set_ports
      set_dyn_ip4: rule_overrides.set_dyn_ip4
      set_dyn_ip6: rule_overrides.set_dyn_ip6
      set_dyn_mac4: rule_overrides.set_dyn_mac4
      set_dyn_mac6: rule_overrides.set_dyn_mac6
    }
    { rules: { rule } }

  describe "create_set_cmd", ->
    it "génère une commande add set de base", ->
      cmd = dyn_sets.create_set_cmd "bridge", "dns-filter-bridge", "my_set", "ipv4_addr", ""
      assert.is_not_nil cmd\find "add set bridge dns-filter-bridge my_set", 1, true
      assert.is_not_nil cmd\find "type ipv4_addr", 1, true

    it "inclut les flags si non vides", ->
      cmd = dyn_sets.create_set_cmd "bridge", "dns-filter-bridge", "my_set", "ipv4_addr", "timeout"
      assert.is_not_nil cmd\find "flags timeout", 1, true

    it "pas de flags si chaîne vide", ->
      cmd = dyn_sets.create_set_cmd "bridge", "tbl", "s", "ipv4_addr", ""
      assert.is_nil cmd\find "flags", 1, true

  describe "collect_rule_sets", ->
    it "plan vide → aucun set", ->
      sets = dyn_sets.collect_rule_sets { rules: {} }
      assert.equals 0, #sets

    it "plan nil → aucun set", ->
      sets = dyn_sets.collect_rule_sets nil
      assert.equals 0, #sets

    it "collecte set_src4 (ipv4_addr interval)", ->
      plan = make_plan { set_src4: "r_test_src4" }
      sets = dyn_sets.collect_rule_sets plan
      found = false
      for _, s in ipairs sets
        if s.name == "r_test_src4"
          found = true
          assert.equals "ipv4_addr", s.type
          assert.equals "interval", s.flags
      assert.is_true found

    it "collecte set_src6 (ipv6_addr interval)", ->
      plan = make_plan { set_src6: "r_test_src6" }
      sets = dyn_sets.collect_rule_sets plan
      found = false
      for _, s in ipairs sets
        if s.name == "r_test_src6"
          found = true
          assert.equals "ipv6_addr", s.type
      assert.is_true found

    it "collecte set_subnet4 (ipv4_addr interval)", ->
      plan = make_plan { set_subnet4: "r_test_subnet4" }
      sets = dyn_sets.collect_rule_sets plan
      found = false
      for _, s in ipairs sets
        if s.name == "r_test_subnet4"
          found = true
          assert.equals "ipv4_addr", s.type
      assert.is_true found

    it "collecte set_subnet6 (ipv6_addr interval)", ->
      plan = make_plan { set_subnet6: "r_test_subnet6" }
      sets = dyn_sets.collect_rule_sets plan
      found = false
      for _, s in ipairs sets
        if s.name == "r_test_subnet6"
          found = true
          assert.equals "ipv6_addr", s.type
      assert.is_true found

    it "collecte set_ports (inet_service, pas de flags)", ->
      plan = make_plan { set_ports: "r_test_ports" }
      sets = dyn_sets.collect_rule_sets plan
      found = false
      for _, s in ipairs sets
        if s.name == "r_test_ports"
          found = true
          assert.equals "inet_service", s.type
          assert.equals "", s.flags
      assert.is_true found

    it "collecte set_dyn_ip4 (ipv4_addr . ipv4_addr timeout)", ->
      plan = make_plan { set_dyn_ip4: "r_test_dyn_ip4" }
      sets = dyn_sets.collect_rule_sets plan
      found = false
      for _, s in ipairs sets
        if s.name == "r_test_dyn_ip4"
          found = true
          assert.equals "ipv4_addr . ipv4_addr", s.type
          assert.equals "timeout", s.flags
      assert.is_true found

    it "collecte set_dyn_ip6 (ipv6_addr . ipv6_addr timeout)", ->
      plan = make_plan { set_dyn_ip6: "r_test_dyn_ip6" }
      sets = dyn_sets.collect_rule_sets plan
      found = false
      for _, s in ipairs sets
        if s.name == "r_test_dyn_ip6"
          found = true
          assert.equals "ipv6_addr . ipv6_addr", s.type
      assert.is_true found

    it "collecte set_dyn_mac4 (ether_addr . ipv4_addr timeout)", ->
      plan = make_plan { set_dyn_mac4: "r_test_dyn_mac4" }
      sets = dyn_sets.collect_rule_sets plan
      found = false
      for _, s in ipairs sets
        if s.name == "r_test_dyn_mac4"
          found = true
          assert.equals "ether_addr . ipv4_addr", s.type
      assert.is_true found

    it "collecte set_dyn_mac6 (ether_addr . ipv6_addr timeout)", ->
      plan = make_plan { set_dyn_mac6: "r_test_dyn_mac6" }
      sets = dyn_sets.collect_rule_sets plan
      found = false
      for _, s in ipairs sets
        if s.name == "r_test_dyn_mac6"
          found = true
          assert.equals "ether_addr . ipv6_addr", s.type
      assert.is_true found

    it "déduplique les sets identiques entre règles", ->
      plan = {
        rules: {
          { set_src4: "shared_set", set_src6: nil }
          { set_src4: "shared_set", set_src6: nil }  -- même nom → dédupliqué
        }
      }
      sets = dyn_sets.collect_rule_sets plan
      count = 0
      for _, s in ipairs sets
        count += 1 if s.name == "shared_set"
      assert.equals 1, count

  describe "generate_set_creation_commands", ->
    it "génère des commandes pour chaque set", ->
      -- On utilise le config stub qui a nft.family="bridge", nft.table="dns-filter-bridge"
      plan = make_plan { set_src4: "r_test_src4", set_dyn_ip4: "r_test_dyn_ip4" }
      cmds = dyn_sets.generate_set_creation_commands plan
      assert.is_true #cmds >= 2
      -- Chaque commande doit contenir "add set"
      for _, cmd in ipairs cmds
        assert.is_not_nil cmd\find "add set", 1, true
