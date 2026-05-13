package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path
package.loaded["config"] = {
  nft = {
    ip_timeout = "2m"
  }
}
package.loaded["filter.conditions.always_true"] = function(cfg)
  return function(args)
    return function(req)
      return true, "always true"
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
print("Testing enriched allow action...")
local test_rule_allow = {
  description = "Allow test",
  rule_id = "allow123",
  conditions = {
    {
      always_true = "test"
    }
  },
  actions = {
    "allow"
  }
}
local eval_fn, metadata = rule.compile_rule({
  nft = {
    ip_timeout = "2m"
  }
}, test_rule_allow, 1)
assert_eq(metadata.worker_only, true, "rule is worker_only due to old-style condition")
assert_eq(#metadata.actions, 1, "one action meta")
assert_eq(metadata.actions[1].worker_only, false, "allow action not worker_only")
assert_eq(metadata.actions[1].capabilities.nft, true, "allow supports nft")
assert_eq(metadata.actions[1].capabilities.worker, true, "allow supports worker")
local verdict, msg, _
verdict, msg, _, _, _ = eval_fn({ })
assert_eq(verdict, true, "allow returns true")
local stmt, err = metadata.actions[1].compile_nft()
assert_eq(stmt, "accept", "allow compiles to accept")
assert_eq(err, nil, "allow compile_nft no error")
print("OK enriched allow")
print("Testing enriched deny action...")
local test_rule_deny = {
  description = "Deny test",
  rule_id = "deny456",
  conditions = {
    {
      always_true = "test"
    }
  },
  actions = {
    "deny"
  }
}
local eval_fn2, metadata2 = rule.compile_rule({
  nft = {
    ip_timeout = "2m"
  }
}, test_rule_deny, 1)
assert_eq(metadata2.worker_only, true, "rule is worker_only due to old-style condition")
assert_eq(metadata2.actions[1].worker_only, false, "deny action not worker_only")
assert_eq(metadata2.actions[1].capabilities.nft, true, "deny supports nft")
local verdict2
verdict2, _, _, _, _ = eval_fn2({ })
assert_eq(verdict2, false, "deny returns false")
local stmt2
stmt2, _ = metadata2.actions[1].compile_nft()
assert_eq(stmt2, "drop", "deny compiles to drop")
print("OK enriched deny")
print("Testing enriched dnsonly action...")
local test_rule_dnsonly = {
  description = "DNS only test",
  rule_id = "dns789",
  conditions = {
    {
      always_true = "test"
    }
  },
  actions = {
    "dnsonly"
  }
}
local eval_fn3, metadata3 = rule.compile_rule({
  nft = {
    ip_timeout = "2m"
  }
}, test_rule_dnsonly, 1)
assert_eq(metadata3.worker_only, true, "dnsonly rule is worker_only")
assert_eq(metadata3.actions[1].worker_only, true, "dnsonly action is worker_only")
assert_eq(metadata3.actions[1].capabilities.nft, false, "dnsonly no nft support")
assert_eq(metadata3.actions[1].capabilities.worker, true, "dnsonly supports worker")
local verdict3
verdict3, _, _, _, _ = eval_fn3({ })
assert_eq(verdict3, "dnsonly", "dnsonly returns string")
local stmt3, err3 = metadata3.actions[1].compile_nft()
assert_eq(stmt3, nil, "dnsonly compile_nft returns nil")
assert_eq(type(err3), "string", "dnsonly compile_nft returns error")
print("OK enriched dnsonly")
return print("\nOK all enriched actions tests passed")
