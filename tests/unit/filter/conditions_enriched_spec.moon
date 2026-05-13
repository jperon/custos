-- Test for enriched conditions
package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

package.loaded["config"] = {
  nft: { ip_timeout: "2m" }
}

-- Stub ipcalc - simple version that matches all IPs for testing
package.loaded["filter.lib.ipcalc"] = {
  Net: (cidr) ->
    -- Return nil for invalid CIDR
    unless cidr and cidr\find("/")
      return nil
    -- Simple stub: matches any IP for testing
    {
      cidr: cidr
      contains: (ip) -> type(ip) == "string"
    }
}

rule = require "filter.rule"

assert_eq = (got, expected, msg) ->
  unless got == expected
    error "#{msg or 'assert_eq failed'}: got=#{tostring got} expected=#{tostring expected}"

print "Testing from_vlan enriched..."

test_rule_vlan = {
  description: "VLAN test"
  rule_id: "vlan123"
  conditions: { { from_vlan: 100 } }
  actions: { "allow" }
}

eval_fn, metadata = rule.compile_rule { nft: { ip_timeout: "2m" } }, test_rule_vlan, 1

-- Check condition metadata
assert_eq #metadata.conditions, 1, "one condition"
assert_eq metadata.conditions[1].name, "from_vlan", "condition name"
assert_eq metadata.conditions[1].worker_only, false, "from_vlan not worker_only"
assert_eq metadata.conditions[1].capabilities.nft_static, true, "from_vlan supports nft_static"

-- Test eval
ok, msg = eval_fn { vlan: 100 }
assert_eq ok, true, "vlan matches"

ok2, msg2 = eval_fn { vlan: 200 }
assert_eq ok2, nil, "vlan doesn't match"

-- Test compile_nft
expr, err = metadata.conditions[1].compile_nft "inet"
assert_eq expr, "vlan id 100", "vlan nft expression"
assert_eq err, nil, "vlan compile_nft no error"

print "OK from_vlan enriched"

print "Testing from_net enriched..."

-- Pre-check: ensure ipcalc stub is loaded
ipcalc = require "filter.lib.ipcalc"
net = ipcalc.Net "192.168.0.0/16"
print "Net object:", net
print "Net.contains test:", net\contains "192.168.1.100"

test_rule_net = {
  description: "Net test"
  rule_id: "net456"
  conditions: { { from_net: "192.168.0.0/16" } }
  actions: { "allow" }
}

eval_fn2, metadata2 = rule.compile_rule { nft: { ip_timeout: "2m" } }, test_rule_net, 1

-- Check condition metadata
print "metadata2.conditions[1]:", metadata2.conditions[1]
print "metadata2.conditions[1]._net:", metadata2.conditions[1]._net
assert_eq metadata2.conditions[1].worker_only, false, "from_net not worker_only"
assert_eq metadata2.conditions[1].capabilities.nft_static, true, "from_net supports nft_static"

-- Test eval with debug
ok3, msg3 = eval_fn2 { src_ip: "192.168.1.100" }
print "ok3:", ok3, "msg3:", msg3
assert_eq ok3, true, "net matches local IP"

ok4, _ = eval_fn2 { src_ip: "10.0.0.1" }
assert_eq ok4, nil, "net doesn't match remote IP"

-- Test compile_nft IPv4
expr2, _ = metadata2.conditions[1].compile_nft "ip"
assert_eq expr2, "ip saddr 192.168.0.0/16", "net nft IPv4 expression"

print "OK from_net enriched"

print "Testing from_mac enriched..."

test_rule_mac = {
  description: "MAC test"
  rule_id: "mac789"
  conditions: { { from_mac: "aa:bb:cc:dd:ee:ff" } }
  actions: { "allow" }
}

eval_fn3, metadata3 = rule.compile_rule { nft: { ip_timeout: "2m" }, macs: {} }, test_rule_mac, 1

-- Check condition metadata
assert_eq metadata3.conditions[1].worker_only, false, "from_mac not worker_only"
assert_eq metadata3.conditions[1].capabilities.nft_static, true, "from_mac supports nft_static"

-- Test eval
ok5, _ = eval_fn3 { mac: "AA:BB:CC:DD:EE:FF" }
assert_eq ok5, true, "mac matches (case insensitive)"

ok6, _ = eval_fn3 { mac: "11:22:33:44:55:66" }
assert_eq ok6, nil, "mac doesn't match"

-- Test compile_nft
expr3, _ = metadata3.conditions[1].compile_nft "inet"
assert_eq expr3, "ether saddr aa:bb:cc:dd:ee:ff", "mac nft expression (lowercase)"

print "OK from_mac enriched"

print "\nOK all enriched conditions tests passed"
