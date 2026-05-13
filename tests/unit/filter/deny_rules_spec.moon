-- Test for deny rules handling
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
      contains: (ip) -> type(ip) == "string"
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

print "Testing deny rules handling..."

-- Config with allow and deny rules
cfg = {
  nft: { ip_timeout: "2m" }
  rules: {
    {
      description: "Allow local net"
      rule_id: "allow_local"
      conditions: { { from_net: "192.168.0.0/16" } }
      actions: { "allow" }
    }
    {
      description: "Deny specific host"
      rule_id: "deny_host"
      conditions: { { from_net: "192.168.1.100/32" } }
      actions: { "deny" }
    }
    {
      description: "Deny all other"
      rule_id: "deny_all"
      conditions: { { from_net: "0.0.0.0/0" } }
      actions: { "deny" }
    }
  }
}

-- Compile rules with enriched metadata
compiled_rules = rule.compile_rules cfg
plan = nft_compiler.compile cfg, compiled_rules.rules_metadata

-- Check action_map has correct verdicts
assert_eq #plan.action_map, 3, "three actions in map"
assert_eq plan.action_map[1].verdict, "accept", "allow rule -> accept"
assert_eq plan.action_map[1].action, "allow", "action is allow"
assert_eq plan.action_map[2].verdict, "drop", "deny rule -> drop"
assert_eq plan.action_map[2].action, "deny", "action is deny"
assert_eq plan.action_map[3].verdict, "drop", "deny rule -> drop"
assert_eq plan.action_map[3].action, "deny", "action is deny"

-- Render and verify
rendered = nft_compiler.render plan, "  ", true

-- Check that drop verdicts are in the action map
assert_contains rendered, "0x4001 : accept", "action_vmap has accept"
assert_contains rendered, "0x4002 : drop", "action_vmap has drop for deny_host"
assert_contains rendered, "0x4003 : drop", "action_vmap has drop for deny_all"

-- Check chains have correct comments
assert_contains rendered, "action=allow", "allow rule has action=allow"
assert_contains rendered, "action=deny", "deny rule has action=deny"

print "Rendered NFT rules with deny:"
print "---"
print rendered
print "---"

print "OK deny rules handling tests passed"
