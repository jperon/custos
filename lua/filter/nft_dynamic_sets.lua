local config = require("config")
local create_set_cmd
create_set_cmd = function(family, table_name, set_name, set_type, flags)
  local parts = {
    "add set " .. tostring(family) .. " " .. tostring(table_name) .. " " .. tostring(set_name),
    "{",
    "type " .. tostring(set_type)
  }
  if flags and #flags > 0 then
    parts[#parts + 1] = "flags " .. tostring(flags)
  end
  parts[#parts + 1] = "}"
  return table.concat(parts, " ")
end
local collect_rule_sets
collect_rule_sets = function(plan)
  if not (plan and plan.rules and #plan.rules > 0) then
    return { }
  end
  local sets_seen = { }
  local sets = { }
  for _, rule in ipairs(plan.rules) do
    if rule.set_src4 and not sets_seen[rule.set_src4] then
      sets_seen[rule.set_src4] = true
      sets[#sets + 1] = {
        name = rule.set_src4,
        type = "ipv4_addr",
        flags = "interval"
      }
    end
    if rule.set_src6 and not sets_seen[rule.set_src6] then
      sets_seen[rule.set_src6] = true
      sets[#sets + 1] = {
        name = rule.set_src6,
        type = "ipv6_addr",
        flags = "interval"
      }
    end
    if rule.set_subnet4 and not sets_seen[rule.set_subnet4] then
      sets_seen[rule.set_subnet4] = true
      sets[#sets + 1] = {
        name = rule.set_subnet4,
        type = "ipv4_addr",
        flags = "interval"
      }
    end
    if rule.set_subnet6 and not sets_seen[rule.set_subnet6] then
      sets_seen[rule.set_subnet6] = true
      sets[#sets + 1] = {
        name = rule.set_subnet6,
        type = "ipv6_addr",
        flags = "interval"
      }
    end
    if rule.set_ports and not sets_seen[rule.set_ports] then
      sets_seen[rule.set_ports] = true
      sets[#sets + 1] = {
        name = rule.set_ports,
        type = "inet_service",
        flags = ""
      }
    end
  end
  return sets
end
local generate_set_creation_commands
generate_set_creation_commands = function(plan)
  local cfg = require("config")
  local family = cfg.nft.family or "bridge"
  local table_name = cfg.nft.table or "dns-filter-bridge"
  local sets = collect_rule_sets(plan)
  local commands = { }
  for _, s in ipairs(sets) do
    local cmd = create_set_cmd(family, table_name, s.name, s.type, s.flags)
    commands[#commands + 1] = cmd
  end
  return commands
end
return {
  generate_set_creation_commands = generate_set_creation_commands,
  collect_rule_sets = collect_rule_sets,
  create_set_cmd = create_set_cmd
}
