-- E2E test for filter + nft integration
package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

package.loaded["config"] = {
  nft: { ip_timeout: "2m" }
  nfqueue: {
    questions: 0
    responses: 1
    captive: 2
    reject: 3
    auth: 4
    sni: 5
  }
}

-- Stub ipcalc
package.loaded["filter.lib.ipcalc"] = {
  Net: (cidr) ->
    unless cidr and cidr\find("/")
      return nil
    is_ipv6 = cidr\find(":") ~= nil
    {
      cidr: cidr
      is_ipv6: is_ipv6
      contains: (ip) =>
        return false unless type(ip) == "string"
        if is_ipv6
          return ip\find(":") ~= nil
        else
          return ip\find("192.168.", 1, true) == 1
    }
}

rule = require "filter.rule"
nft_compiler = require "filter.nft_compiler"
nft_dynamic_sets = require "filter.nft_dynamic_sets"

assert_eq = (got, expected, msg) ->
  unless got == expected
    error "#{msg or 'assert_eq failed'}: got=#{tostring got} expected=#{tostring expected}"

assert_contains = (str, substr, msg) ->
  unless str\find(substr, 1, true)
    error "#{msg or 'assert_contains failed'}: '#{substr}' not found"

print "=== E2E Test: Filter + NFT Integration ==="

-- Step 1: Define realistic filter configuration
print "\n[Step 1] Defining filter configuration..."

filter_cfg = {
  nft: { ip_timeout: "2m" }
  rules: {
    {
      description: "Allow local office net"
      rule_id: "office_net"
      conditions: {
        from_net: "192.168.10.0/24"
        from_mac: "aa:bb:cc:dd:ee:01"
      }
      actions: { "allow" }
    }
    {
      description: "Block specific host"
      rule_id: "blocked_host"
      conditions: {
        from_net: "192.168.10.50/32"
      }
      actions: { "deny" }
    }
    {
      description: "DNS only for guest vlan"
      rule_id: "guest_dns"
      conditions: {
        from_vlan: 999
      }
      actions: { "dnsonly" }
    }
  }
}

print "  - 3 rules defined"

-- Step 2: Compile rules with enriched metadata
print "\n[Step 2] Compiling rules..."

compiled_rules = rule.compile_rules filter_cfg
assert_eq #compiled_rules, 3, "3 compiled rules"
assert_eq type(compiled_rules.rules_metadata), "table", "has metadata"

print "  - Rules compiled successfully"
print "  - Metadata available for", #compiled_rules.rules_metadata, "rules"

-- Step 3: Compile NFT plan
print "\n[Step 3] Compiling NFT plan..."

plan = nft_compiler.compile filter_cfg, compiled_rules.rules_metadata
assert_eq type(plan), "table", "plan created"
assert_eq type(plan.metrics), "table", "has metrics"

print "  - Plan compiled with", plan.metrics.total_rules, "rules"
print "  - NFT-compilable:", plan.metrics.nft_compilable
print "  - Worker-only:", plan.metrics.worker_only
print "  - Conditions compiled:", plan.metrics.conditions_compiled
print "  - Conditions worker-only:", plan.metrics.conditions_worker_only

-- Step 4: Verify rule properties
print "\n[Step 4] Verifying rule properties..."

-- Office net should be nft-compilable (enriched conditions)
assert_eq plan.rules[1].worker_only, false, "office_net is nft-compilable"
assert_eq plan.rules[1].action, "allow", "office_net action is allow"

-- Blocked host should be nft-compilable
assert_eq plan.rules[2].worker_only, false, "blocked_host is nft-compilable"
assert_eq plan.rules[2].action, "deny", "blocked_host action is deny"

-- Guest DNS is worker-only (dnsonly action)
assert_eq plan.rules[3].worker_only, true, "guest_dns is worker-only"
assert_eq plan.rules[3].action, "dnsonly", "guest_dns action is dnsonly"

print "  - Rule properties verified"

-- Step 5: Generate set creation commands
print "\n[Step 5] Generating set creation commands..."

commands = nft_dynamic_sets.generate_set_creation_commands plan
assert_eq type(commands), "table", "commands generated"

print "  -", #commands, "set creation commands generated"
for i, cmd in ipairs commands
  print "    [", i, "]", cmd\sub(1, 60), "..."

-- Step 6: Render NFT rules
print "\n[Step 6] Rendering NFT rules..."

rendered = nft_compiler.render plan, "  ", true
assert_eq type(rendered), "string", "rendered rules"

-- Verify rendered content
assert_contains rendered, "cv_r_office_net", "office_net chain present"
assert_contains rendered, "cv_r_blocked_host", "blocked_host chain present"
assert_contains rendered, "cv_r_guest_dns", "guest_dns chain present"
assert_contains rendered, "ip saddr 192.168.10.0/24", "office net condition"
assert_contains rendered, "ether saddr aa:bb:cc:dd:ee:01", "office mac condition"
assert_contains rendered, "meta mark set 0x4001 counter accept", "office_net accept mark"
assert_contains rendered, "meta mark set 0x4002 counter drop", "blocked_host drop mark"

print "  - NFT rules rendered successfully"
print "  - Key elements verified in output"

-- Step 7: Simulate runtime decision
print "\n[Step 7] Simulating runtime decisions..."

-- Test office host (should match rule 1)
verdict1, msg1 = rule.decide compiled_rules, {
  src_ip: "192.168.10.25"
  mac: "AA:BB:CC:DD:EE:01"
}
assert_eq verdict1, true, "office host allowed"
print "  - Office host:", verdict1, "(", msg1, ")"

-- Test blocked host (should match rule 2)
verdict2, msg2 = rule.decide compiled_rules, {
  src_ip: "192.168.10.50"
  mac: "11:22:33:44:55:66"
}
assert_eq verdict2, false, "blocked host denied"
print "  - Blocked host:", verdict2, "(", msg2, ")"

-- Test guest vlan (should match rule 3 - dnsonly)
verdict3, msg3 = rule.decide compiled_rules, {
  vlan: 999
  src_ip: "10.0.0.1"
}
assert_eq verdict3, "dnsonly", "guest vlan gets dnsonly"
print "  - Guest vlan:", verdict3, "(", msg3, ")"

print "\n=== E2E Test PASSED ==="
print "\nSummary:"
print "- Rules compilation with enriched metadata: OK"
print "- NFT plan compilation with metrics: OK"
print "- Set creation commands: OK"
print "- NFT rules rendering: OK"
print "- Runtime decision simulation: OK"
