package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path
package.loaded["config"] = {
  nft = {
    ip_timeout = "2m"
  }
}
package.loaded["filter.lib.ipcalc"] = {
  Net = function(cidr)
    return {
      cidr = cidr,
      contains = function(self, ip)
        return true
      end
    }
  end
}
local compiler_api = require("filter.compiler_api")
local assert_eq
assert_eq = function(got, expected, msg)
  if not (got == expected) then
    return error(tostring(msg or 'assert_eq failed') .. ": got=" .. tostring(tostring(got)) .. " expected=" .. tostring(tostring(expected)))
  end
end
print("Testing is_new_style...")
assert_eq(compiler_api.is_new_style((function()
  return function() end
end)), false, "function is old style")
assert_eq(compiler_api.is_new_style({
  capabilities = { }
}), true, "table with capabilities is new style")
assert_eq(compiler_api.is_new_style({
  eval = function() end
}), false, "table without capabilities is old style")
print("OK is_new_style")
print("Testing create_allow_action...")
local allow = compiler_api.create_allow_action()
assert_eq(allow.capabilities.nft, true, "allow supports nft")
assert_eq(type(allow.eval), "function", "allow has eval")
local verdict, msg = allow.eval({ })
assert_eq(verdict, true, "allow returns true")
local ok, _ = allow.compile_nft()
assert_eq(ok, "accept", "allow compile_nft returns accept")
print("OK create_allow_action")
print("Testing create_deny_action...")
local deny = compiler_api.create_deny_action()
assert_eq(deny.capabilities.nft, true, "deny supports nft")
verdict, _ = deny.eval({ })
assert_eq(verdict, false, "deny returns false")
ok, _ = deny.compile_nft()
assert_eq(ok, "drop", "deny compile_nft returns drop")
print("OK create_deny_action")
print("Testing create_dnsonly_action...")
local dnsonly = compiler_api.create_dnsonly_action()
assert_eq(dnsonly.capabilities.nft, false, "dnsonly is worker-only")
verdict, _ = dnsonly.eval({ })
assert_eq(verdict, "dnsonly", "dnsonly returns string")
local err
ok, err = dnsonly.compile_nft()
assert_eq(ok, nil, "dnsonly compile_nft returns nil")
print("OK create_dnsonly_action")
print("Testing create_net_condition...")
local net_cond = compiler_api.create_net_condition("src_ip", "192.168.1.0/24")
assert_eq(net_cond.capabilities.nft, true, "net condition supports nft")
ok, _ = net_cond.eval({
  src_ip = "192.168.1.100"
})
assert_eq(ok, true, "net condition matches")
local expr
expr, _ = net_cond.compile_nft("ip")
assert_eq(expr, "ip saddr 192.168.1.0/24", "nft expr for ip family")
local expr6
expr6, _ = net_cond.compile_nft("ip6")
assert_eq(expr6, "ip6 saddr 192.168.1.0/24", "nft expr for ip6 family")
print("OK create_net_condition")
return print("\nOK all compiler_api tests passed")
