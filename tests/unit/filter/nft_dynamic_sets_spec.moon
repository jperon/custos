-- tests/unit/filter/nft_dynamic_sets_spec.moon

describe "filter.nft_dynamic_sets", ->
  dynamic_sets = require "filter.nft_dynamic_sets"

  describe "create_set_cmd", ->
    it "generates simple set creation command", ->
      cmd = dynamic_sets.create_set_cmd "bridge", "dns-filter-bridge", "test_set", "ipv4_addr", "interval"
      assert.is_not_nil cmd
      assert.truthy cmd\find "add set bridge dns-filter-bridge test_set", 1, true
      assert.truthy cmd\find "type ipv4_addr", 1, true
      assert.truthy cmd\find "flags interval", 1, true

    it "generates command without flags when flags is empty", ->
      cmd = dynamic_sets.create_set_cmd "bridge", "my-table", "ports_set", "inet_service", ""
      assert.is_not_nil cmd
      assert.truthy cmd\find "add set bridge my-table ports_set", 1, true
      assert.truthy cmd\find "type inet_service", 1, true
      assert.falsy cmd\find "flags", 1, true

    it "handles different families", ->
      cmd_inet = dynamic_sets.create_set_cmd "inet", "filter", "v4_set", "ipv4_addr", ""
      assert.truthy cmd_inet\find "add set inet filter v4_set", 1, true

  describe "collect_rule_sets", ->
    it "extracts sets from a simple rule", ->
      plan = {
        rules: {
          {
            rule_id: "r_test"
            set_src4: "test_src4"
            source_ipv4: { "192.168.1.0/24" }
            set_ports: "test_dports"
            ports: { "80", "443" }
          }
        }
      }
      sets = dynamic_sets.collect_rule_sets plan
      assert.equal 2, #sets
      
      names = [s.name for s in *sets]
      assert.truthy table.concat(names)\find "test_src4"
      assert.truthy table.concat(names)\find "test_dports"

    it "deduplicates sets with same name", ->
      plan = {
        rules: {
          {
            rule_id: "r_1"
            set_src4: "shared_src4"
            source_ipv4: { "10.0.0.0/8" }
          }
          {
            rule_id: "r_2"
            set_src4: "shared_src4"
            source_ipv4: { "192.168.0.0/16" }
          }
        }
      }
      sets = dynamic_sets.collect_rule_sets plan
      assert.equal 1, #sets
      assert.equal "shared_src4", sets[1].name

    it "handles multiple set types (src4, src6, ports, subnets)", ->
      plan = {
        rules: {
          {
            rule_id: "r_complex"
            set_src4: "src4_set"
            source_ipv4: { "10.0.0.0/8" }
            set_src6: "src6_set"
            source_ipv6: { "fd00::/8" }
            set_subnet4: "subnet4_set"
            subnet_ipv4: { "172.16.0.0/12" }
            set_subnet6: "subnet6_set"
            subnet_ipv6: { "fc00::/7" }
            set_ports: "ports_set"
            ports: { "80", "443", "8080-8090" }
          }
        }
      }
      sets = dynamic_sets.collect_rule_sets plan
      assert.equal 5, #sets
      
      types = [s.type for s in *sets]
      assert.truthy table.concat(types)\find "ipv4_addr" -- should appear twice (src4 and subnet4)
      assert.truthy table.concat(types)\find "ipv6_addr"
      assert.truthy table.concat(types)\find "inet_service"

    it "returns empty array for nil plan", ->
      sets = dynamic_sets.collect_rule_sets nil
      assert.equal 0, #sets

    it "returns empty array for plan with no rules", ->
      plan = { rules: {} }
      sets = dynamic_sets.collect_rule_sets plan
      assert.equal 0, #sets

  describe "generate_set_creation_commands", ->
    it "generates commands for all rule sets", ->
      plan = {
        rules: {
          {
            rule_id: "r_test"
            set_src4: "r_test_src4"
            source_ipv4: { "192.168.0.0/16" }
            set_ports: "r_test_dports"
            ports: { "22", "80", "443" }
          }
        }
      }
      commands = dynamic_sets.generate_set_creation_commands plan
      assert.equal 2, #commands
      
      cmd_text = table.concat commands, "\n"
      assert.truthy cmd_text\find "r_test_src4", 1, true
      assert.truthy cmd_text\find "r_test_dports", 1, true

    it "handles empty plan gracefully", ->
      commands = dynamic_sets.generate_set_creation_commands nil
      assert.equal 0, #commands

    it "generates all command variants", ->
      plan = {
        rules: {
          {
            rule_id: "r_multi"
            set_src4: "src4"
            source_ipv4: { "10.0.0.0/8" }
            set_src6: "src6"
            source_ipv6: { "2001:db8::/32" }
            set_subnet4: "subnet4"
            subnet_ipv4: { "172.16.0.0/12" }
            set_ports: "ports"
            ports: { "443" }
          }
        }
      }
      commands = dynamic_sets.generate_set_creation_commands plan
      assert.equal 4, #commands
