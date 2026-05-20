-- Comprehensive test for all migrated conditions
package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

package.loaded["config"] = {
  nft: { ip_timeout: "2m" }
  times: {
    business_hours: {"09:00", "17:00"}
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
      contains: (ip) => type(ip) == "string"
    }
}

rule = require "filter.rule"
nft_compiler = require "filter.nft_compiler"

assert_eq = (got, expected, msg) ->
  unless got == expected
    error "#{msg or 'assert_eq failed'}: got=#{tostring got} expected=#{tostring expected}"

print "=== Testing All Migrated Conditions ===\n"

-- Test 1: from_vlan (enriched - nft compatible)
print "[Test 1] from_vlan (enriched)..."
cfg_vlan = {
  nft: { ip_timeout: "2m" }
  rules: {{ description: "VLAN test", conditions: { from_vlan: 100 }, actions: { "allow" } }}
}
compiled_vlan = rule.compile_rules cfg_vlan
plan_vlan = nft_compiler.compile cfg_vlan, compiled_vlan.rules_metadata
assert_eq plan_vlan.rules[1].worker_only, false, "from_vlan not worker_only"
assert_eq plan_vlan.rules[1].conditions_meta[1].capabilities.nft, true, "from_vlan nft"
expr_vlan = plan_vlan.rules[1].conditions_meta[1].compile_nft "inet"
assert_eq expr_vlan, "vlan id 100", "vlan id expression"
print "  ✓ from_vlan enriched and compiles to 'vlan id 100'\n"

-- Test 2: from_net (enriched - nft compatible)
print "[Test 2] from_net (enriched)..."
cfg_net = {
  nft: { ip_timeout: "2m" }
  rules: {{ description: "Net test", conditions: { from_net: "192.168.0.0/16" }, actions: { "allow" } }}
}
compiled_net = rule.compile_rules cfg_net
plan_net = nft_compiler.compile cfg_net, compiled_net.rules_metadata
assert_eq plan_net.rules[1].worker_only, false, "from_net not worker_only"
expr_net = plan_net.rules[1].conditions_meta[1].compile_nft "ip"
assert_eq expr_net, "ip saddr 192.168.0.0/16", "net expression"
print "  ✓ from_net enriched and compiles to 'ip saddr <cidr>'\n"

-- Test 3: from_mac (enriched - nft compatible)
print "[Test 3] from_mac (enriched)..."
cfg_mac = {
  nft: { ip_timeout: "2m" }
  rules: {{ description: "MAC test", conditions: { from_mac: "aa:bb:cc:dd:ee:ff" }, actions: { "allow" } }}
}
compiled_mac = rule.compile_rules cfg_mac
plan_mac = nft_compiler.compile cfg_mac, compiled_mac.rules_metadata
assert_eq plan_mac.rules[1].worker_only, false, "from_mac not worker_only"
expr_mac = plan_mac.rules[1].conditions_meta[1].compile_nft "inet"
assert_eq expr_mac, "ether saddr aa:bb:cc:dd:ee:ff", "mac expression"
print "  ✓ from_mac enriched and compiles to 'ether saddr <mac>'\n"

-- Test 4: from_subnet (enriched - nft compatible)
print "[Test 4] from_subnet (enriched)..."
cfg_subnet = {
  nft: { ip_timeout: "2m" }
  rules: {{ description: "Subnet test", conditions: { from_subnet: "10.0.0.0/8" }, actions: { "allow" } }}
}
compiled_subnet = rule.compile_rules cfg_subnet
plan_subnet = nft_compiler.compile cfg_subnet, compiled_subnet.rules_metadata
assert_eq plan_subnet.rules[1].worker_only, false, "from_subnet not worker_only"
expr_subnet = plan_subnet.rules[1].conditions_meta[1].compile_nft "ip"
assert_eq expr_subnet, "ip saddr 10.0.0.0/8", "subnet expression"
print "  ✓ from_subnet enriched and compiles to 'ip saddr <cidr>'\n"

-- Test 5: in_time (enriched - worker only)
print "[Test 5] in_time (enriched, worker-only)..."
cfg_time = {
  nft: { ip_timeout: "2m" }
  rules: {{ description: "Time test", conditions: { in_time: "business_hours" }, actions: { "allow" } }}
}
compiled_time = rule.compile_rules cfg_time
plan_time = nft_compiler.compile cfg_time, compiled_time.rules_metadata
-- Les règles worker-only sont incluses dans plan_rules pour exposer leurs
-- sets dynamiques (set_dyn_*) au worker, même sans condition nft.
assert_eq compiled_time.rules_metadata[1].worker_only, true, "in_time worker_only"
assert_eq compiled_time.rules_metadata[1].conditions[1].capabilities.nft, false, "in_time no nft"
cond_obj = compiled_time.rules_metadata[1].conditions[1]
expr_time, err_time = cond_obj.compile_nft "inet"
assert_eq expr_time, nil, "in_time compile_nft returns nil"
assert_eq type(err_time), "string", "in_time returns error"
print "  ✓ in_time enriched and correctly worker-only\n"

-- Test 6: to_domain (enriched - worker only with dynamic scope)
print "[Test 6] to_domain (enriched, worker-only with dynamic scope)..."
cfg_domain = {
  nft: { ip_timeout: "2m" }
  rules: {{ description: "Domain test", conditions: { to_domain: "example.com" }, actions: { "allow" } }}
}
compiled_domain = rule.compile_rules cfg_domain
plan_domain = nft_compiler.compile cfg_domain, compiled_domain.rules_metadata
assert_eq compiled_domain.rules_metadata[1].worker_only, true, "to_domain worker_only"
assert_eq compiled_domain.rules_metadata[1].conditions[1].creates_dynamic_scope, true, "to_domain creates_dynamic_scope"
expr_domain, err_domain = compiled_domain.rules_metadata[1].conditions[1].compile_nft "inet"
assert_eq expr_domain, nil, "to_domain compile_nft returns nil"
print "  ✓ to_domain enriched, worker-only with dns_scope\n"

-- Test 7: Combined rule with multiple condition types
print "[Test 7] Combined rule (nft + worker conditions)..."
cfg_combined = {
  nft: { ip_timeout: "2m" }
  rules: {
    {
      description: "Combined test"
      conditions: {
        from_net: "192.168.0.0/16"      -- nft-compatible
        in_time: { start: "09:00", end: "17:00" }  -- worker-only
      }
      actions: { "allow" }
    }
  }
}
compiled_combined = rule.compile_rules cfg_combined
plan_combined = nft_compiler.compile cfg_combined, compiled_combined.rules_metadata
assert_eq compiled_combined.rules_metadata[1].worker_only, true, "combined rule worker_only (due to in_time)"
assert_eq #compiled_combined.rules_metadata[1].conditions, 2, "two conditions in meta"
-- Verify both conditions exist by name (pairs order not guaranteed)
nft_count = 0
worker_count = 0
for _, c in ipairs compiled_combined.rules_metadata[1].conditions
  if c.capabilities.nft then nft_count += 1
  else worker_count += 1
assert_eq nft_count, 1, "one nft condition (from_net)"
assert_eq worker_count, 1, "one worker condition (in_time)"
print "  ✓ Combined rule correctly marked worker-only\n"

print "=== All Migrated Conditions Tests PASSED ==="
print "\nSummary:"
print "  • from_vlan: enriched, nft-compatible ✓"
print "  • from_net: enriched, nft-compatible ✓"
print "  • from_mac: enriched, nft-compatible ✓"
print "  • from_subnet: enriched, nft-compatible ✓"
print "  • in_time: enriched, worker-only ✓"
print "  • to_domain: enriched, worker-only + dynamic scope ✓"
print "  • Combined rules: handled correctly ✓"
