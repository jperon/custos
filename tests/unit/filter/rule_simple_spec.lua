package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path
package.loaded["config"] = {
  nft = {
    ip_timeout = "2m"
  }
}
package.loaded["filter.conditions.always_true"] = function(cfg)
  return function(args)
    return function(req)
      return true, "always true: " .. tostring(args)
    end
  end
end
package.loaded["filter.actions.always_allow"] = function(cfg)
  return function(rule)
    return function(req)
      return true, "allowed by " .. tostring(rule.description)
    end
  end
end
local rule = require("filter.rule")
local assert_eq
assert_eq = function(got, expected, msg)
  if not (got == expected) then
    return error(tostring(msg or 'assert_eq failed') .. ": got=" .. tostring(tostring(got)) .. " expected=" .. tostring(tostring(expected)))
  end
end
print("Testing simple compile_rule...")
local test_rule = {
  description = "Simple test",
  rule_id = "simple123",
  conditions = {
    always_true = "test_args"
  },
  actions = {
    "always_allow"
  }
}
local eval_fn, metadata = rule.compile_rule({
  nft = {
    ip_timeout = "2m"
  }
}, test_rule, 1)
assert_eq(type(eval_fn), "function", "returns eval function")
assert_eq(type(metadata), "table", "returns metadata")
assert_eq(metadata.rule_id, "r_simple123", "metadata has rule_id (préfixé r_)")
assert_eq(metadata.worker_only, true, "old-style marked worker_only")
assert_eq(#metadata.conditions, 1, "one condition")
assert_eq(#metadata.actions, 1, "one action")
local verdict, msg, rid, timeout, desc = eval_fn({
  src_ip = "1.2.3.4"
})
assert_eq(verdict, true, "verdict is true")
assert_eq(rid, "r_simple123", "returns rule_id (préfixé r_)")
print("OK simple compile_rule")
return print("\nOK all simple tests passed")
