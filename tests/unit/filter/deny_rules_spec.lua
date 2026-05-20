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
      contains = function(self, ip)
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
local assert_contains
assert_contains = function(str, substr, msg)
  if not (str:find(substr, 1, true)) then
    return error(tostring(msg or 'assert_contains failed') .. ": '" .. tostring(str) .. "' does not contain '" .. tostring(substr) .. "'")
  end
end
print("Testing deny rules handling...")
local cfg = {
  nft = {
    ip_timeout = "2m"
  },
  rules = {
    {
      description = "Allow local net",
      rule_id = "allow_local",
      conditions = {
        from_net = "192.168.0.0/16"
      },
      actions = {
        "allow"
      }
    },
    {
      description = "Deny specific host",
      rule_id = "deny_host",
      conditions = {
        from_net = "192.168.1.100/32"
      },
      actions = {
        "deny"
      }
    },
    {
      description = "Deny all other",
      rule_id = "deny_all",
      conditions = {
        from_net = "0.0.0.0/0"
      },
      actions = {
        "deny"
      }
    }
  }
}
local compiled_rules = rule.compile_rules(cfg)
local plan = nft_compiler.compile(cfg, compiled_rules.rules_metadata)
assert_eq(#plan.action_map, 3, "three actions in map")
assert_eq(plan.action_map[1].verdict, "accept", "allow rule -> accept")
assert_eq(plan.action_map[1].action, "allow", "action is allow")
assert_eq(plan.action_map[2].verdict, "drop", "deny rule -> drop")
assert_eq(plan.action_map[2].action, "deny", "action is deny")
assert_eq(plan.action_map[3].verdict, "drop", "deny rule -> drop")
assert_eq(plan.action_map[3].action, "deny", "action is deny")
local rendered = nft_compiler.render(plan, "  ", true)
assert_contains(rendered, "set 0x4001 counter accept", "allow rule emits accept verdict")
assert_contains(rendered, "set 0x4002 counter drop", "deny_host rule emits drop verdict")
assert_contains(rendered, "set 0x4003 counter drop", "deny_all rule emits drop verdict")
assert_contains(rendered, "action=allow", "allow rule has action=allow")
assert_contains(rendered, "action=deny", "deny rule has action=deny")
print("Rendered NFT rules with deny:")
print("---")
print(rendered)
print("---")
return print("OK deny rules handling tests passed")
