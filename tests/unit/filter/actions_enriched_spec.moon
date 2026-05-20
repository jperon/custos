-- Test for enriched actions API
package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

package.loaded["config"] = {
  nft: { ip_timeout: "2m" }
}

-- Simple old-style condition that always returns true
package.loaded["filter.conditions.always_true"] = (cfg) ->
  (args) ->
    (req) -> true, "always true"

rule = require "filter.rule"

assert_eq = (got, expected, msg) ->
  unless got == expected
    error "#{msg or 'assert_eq failed'}: got=#{tostring got} expected=#{tostring expected}"

print "Testing enriched allow action..."

-- Test allow rule with enriched action
test_rule_allow = {
  description: "Allow test"
  rule_id: "allow123"
  conditions: { always_true: "test" }
  actions: { "allow" }
}

eval_fn, metadata = rule.compile_rule { nft: { ip_timeout: "2m" } }, test_rule_allow, 1

-- Note: rule is worker_only=true because always_true condition is old-style
-- But the action itself is not worker_only
assert_eq metadata.worker_only, true, "rule is worker_only due to old-style condition"
assert_eq #metadata.actions, 1, "one action meta"
assert_eq metadata.actions[1].worker_only, false, "allow action not worker_only"
assert_eq metadata.actions[1].capabilities.nft, true, "allow supports nft"
assert_eq metadata.actions[1].capabilities.worker, true, "allow supports worker"

-- Test eval
verdict, msg, _, _, _ = eval_fn {}
assert_eq verdict, true, "allow returns true"

-- Test compile_nft directly on action meta
stmt, err = metadata.actions[1].compile_nft!
assert_eq stmt, "accept", "allow compiles to accept"
assert_eq err, nil, "allow compile_nft no error"

print "OK enriched allow"

print "Testing enriched deny action..."

test_rule_deny = {
  description: "Deny test"
  rule_id: "deny456"
  conditions: { always_true: "test" }
  actions: { "deny" }
}

eval_fn2, metadata2 = rule.compile_rule { nft: { ip_timeout: "2m" } }, test_rule_deny, 1

-- Rule is worker_only due to old-style condition, but action itself supports nft
assert_eq metadata2.worker_only, true, "rule is worker_only due to old-style condition"
assert_eq metadata2.actions[1].worker_only, false, "deny action not worker_only"
assert_eq metadata2.actions[1].capabilities.nft, true, "deny supports nft"

-- Test eval
verdict2, _, _, _, _ = eval_fn2 {}
assert_eq verdict2, false, "deny returns false"

-- Test compile_nft
stmt2, _ = metadata2.actions[1].compile_nft!
assert_eq stmt2, "drop", "deny compiles to drop"

print "OK enriched deny"

print "Testing enriched dnsonly action..."

test_rule_dnsonly = {
  description: "DNS only test"
  rule_id: "dns789"
  conditions: { always_true: "test" }
  actions: { "dnsonly" }
}

eval_fn3, metadata3 = rule.compile_rule { nft: { ip_timeout: "2m" } }, test_rule_dnsonly, 1

-- Rule is worker_only (condition old-style OR action worker_only)
assert_eq metadata3.worker_only, true, "dnsonly rule is worker_only"
assert_eq metadata3.actions[1].worker_only, true, "dnsonly action is worker_only"
assert_eq metadata3.actions[1].capabilities.nft, false, "dnsonly no nft support"
assert_eq metadata3.actions[1].capabilities.worker, true, "dnsonly supports worker"

-- Test eval : retourne true (verdict allow) + on_response déclaré
verdict3, _, _, _, _ = eval_fn3 {}
assert_eq verdict3, true, "dnsonly returns true"
assert_eq type(metadata3.on_response), "table", "dnsonly on_response list exists"
assert_eq #metadata3.on_response > 0, true, "dnsonly has on_response callback"

-- Test compile_nft
stmt3, err3 = metadata3.actions[1].compile_nft!
assert_eq stmt3, nil, "dnsonly compile_nft returns nil"
assert_eq err3, nil, "dnsonly compile_nft returns nil error"

print "OK enriched dnsonly"

print "Testing strip_AAAA + allow (équivaut à l'ancien allow_ip4)..."

test_rule_strip_aaaa_allow = {
  description: "Strip AAAA + allow test"
  rule_id: "strip_aaaa_allow123"
  conditions: { always_true: "test" }
  actions: { "strip_AAAA", "allow" }
}

eval_fn4, metadata4 = rule.compile_rule { nft: { ip_timeout: "2m" } }, test_rule_strip_aaaa_allow, 1

assert_eq metadata4.worker_only, true, "strip_AAAA+allow rule is worker_only"
assert_eq #metadata4.actions, 2, "strip_AAAA+allow has 2 actions"
assert_eq #metadata4.on_response, 2, "strip_AAAA+allow has 2 on_response callbacks"

verdict4, _, _, _, _ = eval_fn4 {}
assert_eq verdict4, true, "strip_AAAA+allow returns true"

print "OK strip_AAAA + allow"

print "Testing strip_A + allow (équivaut à l'ancien allow_ip6)..."

test_rule_strip_a_allow = {
  description: "Strip A + allow test"
  rule_id: "strip_a_allow456"
  conditions: { always_true: "test" }
  actions: { "strip_A", "allow" }
}

eval_fn5, metadata5 = rule.compile_rule { nft: { ip_timeout: "2m" } }, test_rule_strip_a_allow, 1

assert_eq metadata5.worker_only, true, "strip_A+allow rule is worker_only"
assert_eq #metadata5.actions, 2, "strip_A+allow has 2 actions"
assert_eq #metadata5.on_response, 2, "strip_A+allow has 2 on_response callbacks"

verdict5, _, _, _, _ = eval_fn5 {}
assert_eq verdict5, true, "strip_A+allow returns true"

print "OK strip_A + allow"

print "\nOK all enriched actions tests passed"
