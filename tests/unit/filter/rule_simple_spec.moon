-- Simple test for filter/rule.moon
package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

package.loaded["config"] = {
  nft: { ip_timeout: "2m" }
}

-- Simple old-style condition that always returns true
package.loaded["filter.conditions.always_true"] = (cfg) ->
  (args) ->
    (req) -> true, "always true: #{args}"

-- Simple old-style action that allows
package.loaded["filter.actions.always_allow"] = (cfg) ->
  (rule) ->
    (req) -> true, "allowed by #{rule.description}"

rule = require "filter.rule"

assert_eq = (got, expected, msg) ->
  unless got == expected
    error "#{msg or 'assert_eq failed'}: got=#{tostring got} expected=#{tostring expected}"

print "Testing simple compile_rule..."

test_rule = {
  description: "Simple test"
  rule_id: "simple123"
  conditions: { { always_true: "test_args" } }
  actions: { "always_allow" }
}

eval_fn, metadata = rule.compile_rule { nft: { ip_timeout: "2m" } }, test_rule, 1

assert_eq type(eval_fn), "function", "returns eval function"
assert_eq type(metadata), "table", "returns metadata"
assert_eq metadata.rule_id, "simple123", "metadata has rule_id"
assert_eq metadata.worker_only, true, "old-style marked worker_only"
assert_eq #metadata.conditions, 1, "one condition"
assert_eq #metadata.actions, 1, "one action"

-- Test evaluation
verdict, msg, rid, timeout, desc = eval_fn { src_ip: "1.2.3.4" }
assert_eq verdict, true, "verdict is true"
assert_eq rid, "simple123", "returns rule_id"

print "OK simple compile_rule"

print "\nOK all simple tests passed"
