package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

-- Stub config
package.loaded["config"] = {
  nft: { ip_timeout: "2m" }
}

-- Stub ipcalc
package.loaded["filter.lib.ipcalc"] = {
  Net: (cidr) -> {
    cidr: cidr
    contains: (ip) => true
  }
}

compiler_api = require "filter.compiler_api"

assert_eq = (got, expected, msg) ->
  unless got == expected
    error "#{msg or 'assert_eq failed'}: got=#{tostring got} expected=#{tostring expected}"

-- Test is_new_style
print "Testing is_new_style..."
assert_eq compiler_api.is_new_style((-> ->)), false, "function is old style"
assert_eq compiler_api.is_new_style({ capabilities: {} }), true, "table with capabilities is new style"
assert_eq compiler_api.is_new_style({ eval: -> }), false, "table without capabilities is old style"
print "OK is_new_style"

-- Test create_allow_action
print "Testing create_allow_action..."
allow = compiler_api.create_allow_action!
assert_eq allow.capabilities.nft, true, "allow supports nft"
assert_eq type(allow.eval), "function", "allow has eval"
verdict, msg = allow.eval {}
assert_eq verdict, true, "allow returns true"
ok, _ = allow.compile_nft!
assert_eq ok, "accept", "allow compile_nft returns accept"
print "OK create_allow_action"

-- Test create_deny_action
print "Testing create_deny_action..."
deny = compiler_api.create_deny_action!
assert_eq deny.capabilities.nft, true, "deny supports nft"
verdict, _ = deny.eval {}
assert_eq verdict, false, "deny returns false"
ok, _ = deny.compile_nft!
assert_eq ok, "drop", "deny compile_nft returns drop"
print "OK create_deny_action"

-- Test create_dnsonly_action
print "Testing create_dnsonly_action..."
dnsonly = compiler_api.create_dnsonly_action!
assert_eq dnsonly.capabilities.nft, false, "dnsonly is worker-only"
verdict, _ = dnsonly.eval {}
assert_eq verdict, "dnsonly", "dnsonly returns string"
ok, err = dnsonly.compile_nft!
assert_eq ok, nil, "dnsonly compile_nft returns nil"
print "OK create_dnsonly_action"

-- Test create_net_condition
print "Testing create_net_condition..."
net_cond = compiler_api.create_net_condition "src_ip", "192.168.1.0/24"
assert_eq net_cond.capabilities.nft, true, "net condition supports nft"
ok, _ = net_cond.eval { src_ip: "192.168.1.100" }
assert_eq ok, true, "net condition matches"

expr, _ = net_cond.compile_nft "ip"
assert_eq expr, "ip saddr 192.168.1.0/24", "nft expr for ip family"

expr6, _ = net_cond.compile_nft "ip6"
assert_eq expr6, "ip6 saddr 192.168.1.0/24", "nft expr for ip6 family"
print "OK create_net_condition"

print "\nOK all compiler_api tests passed"
