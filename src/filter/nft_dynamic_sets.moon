-- src/filter/nft_dynamic_sets.moon
-- Dynamic set creation API for per-rule nftables sets.
--
-- Generates "nft add set" commands from compiled filter rules.
-- These commands are executed at runtime instead of embedding set
-- definitions directly in the template.

config = require "config"

--- Generate set creation command for a single set.
-- @tparam string family nftables family (bridge, inet, etc)
-- @tparam string table_name table name
-- @tparam string set_name set name
-- @tparam string set_type set element type (ipv4_addr, ipv6_addr, inet_service, etc)
-- @tparam string flags set flags (interval, timeout, etc) - empty string if none
-- @treturn string nft command string
create_set_cmd = (family, table_name, set_name, set_type, flags) ->
  parts = {
    "add set #{family} #{table_name} #{set_name}"
    "{"
    "type #{set_type}"
  }
  
  if flags and #flags > 0
    parts[#parts + 1] = "flags #{flags}"
  
  parts[#parts + 1] = "}"
  table.concat parts, " "

--- Extract all unique sets from compiled rules plan.
-- Returns a set of {name, type, flags} entries to avoid duplicates.
-- @tparam table plan compiled rules plan from nft_compiler.compile()
-- @treturn table array of {name, type, flags} sets
collect_rule_sets = (plan) ->
  return {} unless plan and plan.rules and #plan.rules > 0
  
  sets_seen = {}
  sets = {}
  
  for _, rule in ipairs plan.rules
    -- Source IPv4 set
    if rule.set_src4 and not sets_seen[rule.set_src4]
      sets_seen[rule.set_src4] = true
      sets[#sets + 1] = {
        name: rule.set_src4
        type: "ipv4_addr"
        flags: "interval"
      }
    
    -- Source IPv6 set
    if rule.set_src6 and not sets_seen[rule.set_src6]
      sets_seen[rule.set_src6] = true
      sets[#sets + 1] = {
        name: rule.set_src6
        type: "ipv6_addr"
        flags: "interval"
      }
    
    -- Source subnet IPv4 set
    if rule.set_subnet4 and not sets_seen[rule.set_subnet4]
      sets_seen[rule.set_subnet4] = true
      sets[#sets + 1] = {
        name: rule.set_subnet4
        type: "ipv4_addr"
        flags: "interval"
      }
    
    -- Source subnet IPv6 set
    if rule.set_subnet6 and not sets_seen[rule.set_subnet6]
      sets_seen[rule.set_subnet6] = true
      sets[#sets + 1] = {
        name: rule.set_subnet6
        type: "ipv6_addr"
        flags: "interval"
      }
    
    -- Destination ports set
    if rule.set_ports and not sets_seen[rule.set_ports]
      sets_seen[rule.set_ports] = true
      sets[#sets + 1] = {
        name: rule.set_ports
        type: "inet_service"
        flags: ""
      }

    dynamic_sets = {
      { name: rule.set_dyn_ip4, type: "ipv4_addr . ipv4_addr", flags: "timeout" }
      { name: rule.set_dyn_ip6, type: "ipv6_addr . ipv6_addr", flags: "timeout" }
      { name: rule.set_dyn_mac4, type: "ether_addr . ipv4_addr", flags: "timeout" }
      { name: rule.set_dyn_mac6, type: "ether_addr . ipv6_addr", flags: "timeout" }
    }
    for _, dyn in ipairs dynamic_sets
      if dyn.name and not sets_seen[dyn.name]
        sets_seen[dyn.name] = true
        sets[#sets + 1] = dyn
  
  sets

--- Generate all "nft add set" commands for a compiled rules plan.
-- @tparam table plan compiled rules plan from nft_compiler.compile()
-- @treturn table array of command strings
generate_set_creation_commands = (plan) ->
  cfg = require "config"
  family = cfg.nft.family or "bridge"
  table_name = cfg.nft.table or "dns-filter-bridge"
  
  sets = collect_rule_sets plan
  commands = {}
  
  for _, s in ipairs sets
    cmd = create_set_cmd family, table_name, s.name, s.type, s.flags
    commands[#commands + 1] = cmd
  
  commands

{
  :generate_set_creation_commands
  :collect_rule_sets
  :create_set_cmd
}
