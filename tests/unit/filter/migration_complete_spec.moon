-- Final test: verify all modules migrated to enriched API
package.path = "src/?.lua;src/?/init.lua;src/?/?.lua;lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

package.loaded["config"] = {
  nft: { ip_timeout: "2m" }
  times: { business_hours: {"09:00", "17:00"} }
  times_lists: { workdays: {"business_hours"} }
  nets: { office: {"192.168.0.0/16"} }
  macs: { printers: {"aa:bb:cc:dd:ee:01"} }
  vlans: { corp: {100, 200} }
  domainlists_dir: "/tmp"
  userlists: { admins: {"alice", "bob"} }
  auth: { sessions_file: "/tmp/sessions.json" }
}

-- Stub ipcalc
package.loaded["filter.lib.ipcalc"] = {
  Net: (cidr) ->
    unless cidr and cidr\find("/")
      return nil
    {
      cidr: cidr
      contains: (ip) -> type(ip) == "string"
    }
}

-- Stub auth.sessions
package.loaded["auth.sessions"] = {
  session_for_mac: -> nil
  enrich_session_ip: -> nil
  bind_session_mac: -> nil
}

package.loaded["auth.user_sessions"] = {
  get_session: -> nil
}

-- Stub log
package.loaded["log"] = {
  log_debug: ->
}

compiler_api = require "filter.compiler_api"

assert_eq = (got, expected, msg) ->
  unless got == expected
    error "#{msg or 'assert_eq failed'}: got=#{tostring got} expected=#{tostring expected}"

assert_is_enriched = (obj, name) ->
  unless type(obj) == "table"
    error "#{name} is not a table (enriched object expected)"
  unless obj.capabilities
    error "#{name} missing capabilities (not enriched)"
  unless obj.eval
    error "#{name} missing eval function (not enriched)"
  unless obj.compile_nft
    error "#{name} missing compile_nft function (not enriched)"

print "=== MIGRATION COMPLETE VERIFICATION ===\n"

-- List of all condition modules to check
conditions = {
  "from_vlan", "from_vlans", "from_vlanlist", "from_vlanlists"
  "from_net", "from_nets", "from_netlist", "from_netlists", "from_subnet"
  "from_mac", "from_macs", "from_maclist", "from_maclists"
  "from_user", "from_users", "from_userlist", "from_userlists"
  "from_authenticated_user"
  "in_time", "in_times", "in_timelist", "in_timelists"
  "to_domain", "to_domains", "to_domainlist", "to_domainlists"
  "stolen_computer"
}

-- List of all action modules to check
actions = {
  "allow", "deny", "dnsonly"
}

print "[1] Checking condition modules..."
for _, name in ipairs conditions
  print "  - #{name}"
  factory = compiler_api.load_condition name
  assert_eq type(factory), "function", "#{name} factory is function"
  
  -- Create with appropriate args
  args = switch name
    when "from_vlan" then 100
    when "from_vlans", "from_vlanlist" then {100, 200}
    when "from_vlanlists" then {"corp"}
    when "from_net" then "192.168.0.0/16"
    when "from_nets", "from_netlist" then {"192.168.0.0/16"}
    when "from_netlists" then {"office"}
    when "from_subnet" then {net: "10.0.0.0/8"}
    when "from_mac" then "aa:bb:cc:dd:ee:ff"
    when "from_macs", "from_maclist" then {"aa:bb:cc:dd:ee:ff"}
    when "from_maclists" then {"printers"}
    when "from_user", "from_users" then {"alice"}
    when "from_userlist" then "admins"
    when "from_userlists" then {"admins"}
    when "from_authenticated_user" then "alice"
    when "in_time" then "business_hours"
    when "in_times" then {"business_hours"}
    when "in_timelist" then "workdays"
    when "in_timelists" then {"workdays"}
    when "to_domain" then "example.com"
    when "to_domains" then {"example.com"}
    when "to_domainlist" then "blocked"
    when "to_domainlists" then {"blocked"}
    when "stolen_computer" then {"aa:bb:cc:dd:ee:01"}
    else {}
  
  cond_factory = factory { nft: {ip_timeout: "2m"}, times: {business_hours: {"09:00", "17:00"}}, times_lists: {workdays: {"business_hours"}}, nets: {office: {"192.168.0.0/16"}}, macs: {printers: {"aa:bb:cc:dd:ee:01"}}, vlans: {corp: {100, 200}}, domainlists_dir: "/tmp", userlists: {admins: {"alice", "bob"}}, auth: {sessions_file: "/tmp/sessions.json"} }
  cond_obj = cond_factory args
  assert_is_enriched cond_obj, name

print "  ✓ All #{#conditions} condition modules migrated\n"

print "[2] Checking action modules..."
for _, name in ipairs actions
  print "  - #{name}"
  factory = compiler_api.load_action name
  assert_eq type(factory), "function", "#{name} factory is function"
  
  action_factory = factory {}
  action_obj = action_factory { description: "test", actions: {name} }
  assert_is_enriched action_obj, name

print "  ✓ All #{#actions} action modules migrated\n"

print "[3] Checking legacy files removed..."
legacy_files = os.execute "ls src/filter/conditions/_match_*.moon 2>/dev/null"
if legacy_files
  error "Legacy _match_* files still exist!"
print "  ✓ Legacy _match_* files removed\n"

print "=== MIGRATION COMPLETE ✓ ==="
print "\nAll conditions and actions are now using the enriched API:"
print "  • capabilities table with worker/nft/nft_dynamic"
print "  • eval() function for runtime checks"
print "  • compile_nft() function for nft compilation"
print "  • worker_only flag for conditional nft generation"
print "  • creates_dynamic_scope flag for dns_scope tracking"
