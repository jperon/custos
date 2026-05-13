package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path
package.loaded["config"] = {
  nft = {
    ip_timeout = "2m"
  }
}
package.loaded["filter.lib.ipcalc"] = {
  Net = function(cidr)
    if not (cidr and cidr:find("/")) then
      return nil
    end
    return {
      cidr = cidr,
      contains = function(ip)
        return type(ip) == "string"
      end
    }
  end
}
local nft_compiler = require("filter.nft_compiler")
local rule = require("filter.rule")
local assert_eq
assert_eq = function(got, expected, msg)
  if not (got == expected) then
    return error(tostring(msg or 'assert_eq failed') .. ": got=" .. tostring(tostring(got)) .. " expected=" .. tostring(tostring(expected)))
  end
end
print("Testing compilation metrics...")
local cfg = {
  nft = {
    ip_timeout = "2m"
  },
  rules = {
    {
      description = "Enriched net rule",
      rule_id = "net1",
      conditions = {
        {
          from_net = "192.168.0.0/16"
        }
      },
      actions = {
        "allow"
      }
    },
    {
      description = "Enriched mac rule",
      rule_id = "mac1",
      conditions = {
        {
          from_mac = "aa:bb:cc:dd:ee:ff"
        }
      },
      actions = {
        "allow"
      }
    },
    {
      description = "Legacy condition rule",
      rule_id = "legacy1",
      conditions = {
        {
          from_vlan = 100
        }
      },
      actions = {
        "deny"
      }
    }
  }
}
local compiled_rules = rule.compile_rules(cfg)
local plan = nft_compiler.compile(cfg, compiled_rules.rules_metadata)
assert_eq(type(plan.metrics), "table", "plan has metrics")
assert_eq(plan.metrics.total_rules, 3, "3 total rules")
assert_eq(plan.metrics.nft_compilable, 2, "2 nft-compilable rules")
assert_eq(plan.metrics.worker_only, 1, "1 worker-only rule")
assert_eq(plan.metrics.conditions_compiled, 2, "2 conditions compiled to nft")
assert_eq(plan.metrics.conditions_worker_only, 1, "1 condition worker-only")
print("Metrics:")
print("  total_rules:", plan.metrics.total_rules)
print("  nft_compilable:", plan.metrics.nft_compilable)
print("  worker_only:", plan.metrics.worker_only)
print("  conditions_compiled:", plan.metrics.conditions_compiled)
print("  conditions_worker_only:", plan.metrics.conditions_worker_only)
return print("OK compilation metrics tests passed")
