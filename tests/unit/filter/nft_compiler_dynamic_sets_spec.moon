package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

package.loaded["config"] = {
  nft: {
    family: "bridge"
    table: "dns-filter-bridge"
    set_ip4: "ip4_allowed"
    set_ip6: "ip6_allowed"
    set_mac4: "mac4_allowed"
    set_mac6: "mac6_allowed"
    ip_timeout: "2m"
  }
}

ffi = require "ffi"
pcall ->
  ffi.cdef [[
    typedef struct { long tv_sec; long tv_nsec; } timespec_t;
    struct pollfd { int fd; short events; short revents; };
  ]]
package.loaded["ffi_defs"] = {
  ffi: ffi
  libc: ffi.C
  libnfq: {}
  libnft: {}
}

package.loaded["log"] = {
  log_warn: -> nil
}

nft_queue = require "nft_queue"
nft_compiler = require "filter.nft_compiler"
dyn_sets = require "filter.nft_dynamic_sets"

assert_eq = (got, expected, msg) ->
  unless got == expected
    error "#{msg or 'assert_eq failed'}: got=#{tostring got} expected=#{tostring expected}"

assert_has = (haystack, needle, msg) ->
  unless haystack\find needle, 1, true
    error "#{msg or 'missing fragment'}: #{needle}"

assert_eq nft_queue.get_set_name("ip4", "test"), "rule_test_ip4", "ip4 set name"
assert_eq nft_queue.get_set_name("ip6", "test"), "rule_test_ip6", "ip6 set name"
assert_eq nft_queue.get_set_name("mac4", "test"), "rule_test_mac4", "mac4 set name"
assert_eq nft_queue.get_set_name("mac6", "test"), "rule_test_mac6", "mac6 set name"

cmd = nft_queue.cmd_for "mac4", "aa:bb:cc:dd:ee:ff", "10.0.0.1", "test", "60s"
assert_has cmd, "rule_test_mac4", "mac4 cmd set"

plan = nft_compiler.compile {
  rules: {
    {
      rule_id: "adult"
      conditions: {
        { to_domain: "example.org" }
      }
      actions: { "allow" }
    }
  }
}

sets = dyn_sets.collect_rule_sets plan
seen = {}
for _, s in ipairs sets
  seen[s.name] = s

assert_eq seen.rule_adult_ip4.type, "ipv4_addr . ipv4_addr", "ip4 dynamic type"
assert_eq seen.rule_adult_ip6.type, "ipv6_addr . ipv6_addr", "ip6 dynamic type"
assert_eq seen.rule_adult_mac4.type, "ether_addr . ipv4_addr", "mac4 dynamic type"
assert_eq seen.rule_adult_mac6.type, "ether_addr . ipv6_addr", "mac6 dynamic type"

rendered = nft_compiler.render plan
assert_has rendered, "set rule_adult_ip4", "render ip4 set"
assert_has rendered, "set rule_adult_mac4", "render mac4 set"
assert_has rendered, "ether saddr . ip daddr @rule_adult_mac4", "render mac4 match"
assert_has rendered, "ip saddr . ip daddr @rule_adult_ip4", "render ip4 match"

print "OK nft compiler dynamic sets"
