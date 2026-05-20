-- Final test: verify all modules migrated to enriched API
-- Ne pas ajouter src/ au package.path : les .lua compilés sont dans lua/,
-- et des .lua parasites dans src/ pollueraient les suites suivantes.
package.path = "lua/?.lua;lua/?/init.lua;lua/?/?.lua;" .. package.path

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
      contains: (ip) => type(ip) == "string"
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
  -- compile_nft est optionnel : les conditions worker-only ne le définissent
  -- pas. capabilities.nft = true requiert en revanche compile_nft.
  if obj.capabilities.nft and not obj.compile_nft
    error "#{name} déclare nft:true mais n'a pas compile_nft"

print "=== MIGRATION COMPLETE VERIFICATION ===\n"

-- List of all condition modules to check. Les variantes _list/_lists et le
-- pluriel sont auto-générées par compiler_api.load_condition (cf. README).
conditions = {
  "from_vlan", "from_vlans", "from_vlan_list", "from_vlan_lists"
  "from_net", "from_nets", "from_net_list", "from_net_lists", "from_subnet"
  "from_mac", "from_macs", "from_mac_list", "from_mac_lists"
  "from_user", "from_users", "from_user_list", "from_user_lists"
  "in_time", "in_times", "in_time_list", "in_time_lists"
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
    when "from_vlans" then {100, 200}
    when "from_vlan_list" then "corp"
    when "from_vlan_lists" then {"corp"}
    when "from_net" then "192.168.0.0/16"
    when "from_nets" then {"192.168.0.0/16"}
    when "from_net_list" then "office"
    when "from_net_lists" then {"office"}
    when "from_subnet" then {net: "10.0.0.0/8"}
    when "from_mac" then "aa:bb:cc:dd:ee:ff"
    when "from_macs" then {"aa:bb:cc:dd:ee:ff"}
    when "from_mac_list" then "printers"
    when "from_mac_lists" then {"printers"}
    when "from_user" then "alice"
    when "from_users" then {"alice"}
    when "from_user_list" then "admins"
    when "from_user_lists" then {"admins"}
    when "in_time" then "business_hours"
    when "in_times" then {"business_hours"}
    when "in_time_list" then "workdays"
    when "in_time_lists" then {"workdays"}
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
-- os.execute renvoie un code de sortie variable selon Lua/LuaJIT : on lit
-- explicitement la sortie de la commande pour vérifier l'absence des fichiers.
pipe = io.popen "ls src/filter/conditions/_match_*.moon 2>/dev/null"
has_legacy = false
if pipe
  has_legacy = pipe\read("*a") ~= ""
  pipe\close!
if has_legacy
  error "Legacy _match_* files still exist!"
print "  ✓ Legacy _match_* files removed\n"

print "=== MIGRATION COMPLETE ✓ ==="
print "\nAll conditions and actions are now using the enriched API:"
print "  • capabilities table with worker/nft/nft_dynamic"
print "  • eval() function for runtime checks"
print "  • compile_nft() function for nft compilation"
print "  • worker_only flag for conditional nft generation"
print "  • creates_dynamic_scope flag for dns_scope tracking"
