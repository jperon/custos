-- Test for nft_compiler with enriched metadata
package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

package.loaded["config"] = {
  nft: { ip_timeout: "2m" }
}

-- Stub ipcalc
package.loaded["filter.lib.ipcalc"] = {
  Net: (cidr) ->
    unless cidr and cidr\find("/")
      return nil
    {
      cidr: cidr
      contains: (ip) => type(ip) == "string"
    }
}

nft_compiler = require "filter.nft_compiler"
rule = require "filter.rule"

assert_eq = (got, expected, msg) ->
  unless got == expected
    error "#{msg or 'assert_eq failed'}: got=#{tostring got} expected=#{tostring expected}"

assert_contains = (str, substr, msg) ->
  unless str\find(substr, 1, true)
    error "#{msg or 'assert_contains failed'}: '#{str}' does not contain '#{substr}'"

print "Testing nft_compiler with enriched metadata..."

-- Config with enriched conditions
cfg = {
  nft: { ip_timeout: "2m" }
  rules: {
    {
      description: "VLAN 100 rule"
      rule_id: "vlan_rule_1"
      conditions: { from_vlan: 100 }
      actions: { "allow" }
    }
    {
      description: "Net rule"
      rule_id: "net_rule_1"
      conditions: { from_net: "192.168.0.0/16" }
      actions: { "allow" }
    }
  }
}

-- Compile rules with enriched metadata
compiled_rules = rule.compile_rules cfg
assert_eq type(compiled_rules), "table", "compile_rules returns table"
assert_eq #compiled_rules, 2, "two compiled rules"
assert_eq type(compiled_rules.rules_metadata), "table", "has rules_metadata"
assert_eq #compiled_rules.rules_metadata, 2, "metadata for both rules"

-- Compile nft plan with metadata
plan = nft_compiler.compile cfg, compiled_rules.rules_metadata
assert_eq type(plan), "table", "compile returns plan"
assert_eq #plan.rules, 2, "plan has two rules"
assert_eq plan.rules[1].worker_only, false, "rule 1 not worker_only (from_vlan is nft-compilable)"
assert_eq plan.rules[2].worker_only, false, "rule 2 not worker_only (enriched from_net)"

-- Check that conditions_meta are attached
assert_eq type(plan.rules[2].conditions_meta), "table", "rule 2 has conditions_meta"
assert_eq #plan.rules[2].conditions_meta, 1, "one condition meta"
assert_eq plan.rules[2].conditions_meta[1].name, "from_net", "condition is from_net"
assert_eq plan.rules[2].conditions_meta[1].worker_only, false, "from_net not worker_only"
assert_eq plan.rules[2].conditions_meta[1].capabilities.nft, true, "from_net supports nft"

-- Test compile_conditions_nft function
exprs = nft_compiler.compile_conditions_nft plan.rules[2].conditions_meta, "ip"
assert_eq #exprs, 1, "one compiled expression"
assert_eq exprs[1], "ip saddr 192.168.0.0/16", "correct nft expression"

-- Render the plan
rendered = nft_compiler.render plan, "  ", true
assert_eq type(rendered), "string", "render returns string"
assert_contains rendered, "vlan id 100", "rendered contains vlan expression"
assert_contains rendered, "ip saddr 192.168.0.0/16", "rendered contains net expression"
-- rule_id.generate préfixe "rule_" → cv_rule_rule_<id>
assert_contains rendered, "cv_rule_rule_vlan_rule_1", "rendered contains vlan rule chain"
assert_contains rendered, "cv_rule_rule_net_rule_1", "rendered contains net rule chain"

print "Rendered NFT rules:"
print "---"
print rendered
print "---"

print "OK nft_compiler with enriched metadata tests passed"
