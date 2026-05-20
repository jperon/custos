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

-- Test eval
verdict3, _, _, _, _ = eval_fn3 {}
assert_eq verdict3, "dnsonly", "dnsonly returns string"

-- Test compile_nft
stmt3, err3 = metadata3.actions[1].compile_nft!
assert_eq stmt3, nil, "dnsonly compile_nft returns nil"
assert_eq err3, nil, "dnsonly compile_nft returns nil error"

print "OK enriched dnsonly"

print "Testing enriched allow_ip4 action..."

test_rule_allow_ip4 = {
  description: "Allow IPv4 only test"
  rule_id: "allow4123"
  conditions: { always_true: "test" }
  actions: { "allow_ip4" }
}

eval_fn4, metadata4 = rule.compile_rule { nft: { ip_timeout: "2m" } }, test_rule_allow_ip4, 1

-- Rule is worker_only (action worker_only)
assert_eq metadata4.worker_only, true, "allow_ip4 rule is worker_only"
assert_eq metadata4.actions[1].worker_only, true, "allow_ip4 action is worker_only"
assert_eq metadata4.actions[1].capabilities.nft, false, "allow_ip4 no nft support"
assert_eq metadata4.actions[1].capabilities.worker, true, "allow_ip4 supports worker"

-- Test eval
verdict4, _, _, _, _ = eval_fn4 {}
assert_eq verdict4, "allow_ip4", "allow_ip4 returns string"

-- Test compile_nft
stmt4, err4 = metadata4.actions[1].compile_nft!
assert_eq stmt4, nil, "allow_ip4 compile_nft returns nil"
assert_eq err4, nil, "allow_ip4 compile_nft returns nil error"

print "OK enriched allow_ip4"

print "Testing enriched allow_ip6 action..."

test_rule_allow_ip6 = {
  description: "Allow IPv6 only test"
  rule_id: "allow6456"
  conditions: { always_true: "test" }
  actions: { "allow_ip6" }
}

eval_fn5, metadata5 = rule.compile_rule { nft: { ip_timeout: "2m" } }, test_rule_allow_ip6, 1

-- Rule is worker_only (action worker_only)
assert_eq metadata5.worker_only, true, "allow_ip6 rule is worker_only"
assert_eq metadata5.actions[1].worker_only, true, "allow_ip6 action is worker_only"
assert_eq metadata5.actions[1].capabilities.nft, false, "allow_ip6 no nft support"
assert_eq metadata5.actions[1].capabilities.worker, true, "allow_ip6 supports worker"

-- Test eval
verdict5, _, _, _, _ = eval_fn5 {}
assert_eq verdict5, "allow_ip6", "allow_ip6 returns string"

-- Test compile_nft
stmt5, err5 = metadata5.actions[1].compile_nft!
assert_eq stmt5, nil, "allow_ip6 compile_nft returns nil"
assert_eq err5, nil, "allow_ip6 compile_nft returns nil error"

print "OK enriched allow_ip6"

print "\nOK all enriched actions tests passed"
