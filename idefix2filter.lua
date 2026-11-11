package.path = table.concat({
  "lua/?.lua",
  "lua/?/init.lua",
  "lua/?/?.lua",
  package.path
}, ";")
local json = require("lib.json")
local MACLIST_GROUPS = {
  "profs",
  "abbes",
  "eleves_limites",
  "salon_profs",
  "defaut"
}
local PROFILE_MAP = {
  ["Internet autorisé (filtré par catégories \"large\")"] = "profs",
  ["Internet filtré par défaut (prieuré)"] = "defaut",
  ["Internet limité (liste blanche)"] = "eleves_limites"
}
local ABBES_LISTS = {
  "custom/addenda_religieux",
  "custom/addenda_auth",
  "custom/addenda_banque",
  "custom/addenda_cloud",
  "custom/addenda_communication",
  "custom/addenda_courriel",
  "custom/addenda_gps",
  "custom/addenda_maj",
  "custom/addenda_peripheriques",
  "custom/addenda_stemarie",
  "custom/default_fsspx",
  "custom/limite_eleves_fsspx"
}
local ELEVES_LISTS = {
  "custom/addenda_apple",
  "custom/addenda_cloud",
  "custom/addenda_courriel",
  "custom/addenda_maj",
  "custom/addenda_peripheriques",
  "custom/addenda_stemarie",
  "custom/default_fsspx",
  "custom/limite_eleves_fsspx"
}
local clean_domain
clean_domain = function(domain)
  if not (domain) then
    return nil
  end
  domain = domain:gsub("^%s*(.-)%s*$", "%1")
  if domain == "" then
    return nil
  end
  domain = domain:gsub("^%*. ", "")
  return domain:lower()
end
local clean_domains
clean_domains = function(domains)
  local cleaned = { }
  for _index_0 = 1, #domains do
    local d = domains[_index_0]
    local c = clean_domain(d)
    if c then
      table.insert(cleaned, c)
    end
  end
  table.sort(cleaned)
  return cleaned
end
local ESCAPES = {
  ['"'] = '\\"',
  ["\\"] = "\\\\",
  ["\n"] = "\\n",
  ["\r"] = "\\r",
  ["\t"] = "\\t"
}
local escape_string
escape_string = function(s)
  return '"' .. (tostring(s):gsub('[%c"\\]', function(c)
    return ESCAPES[c] or string.format("\\%03d", c:byte())
  end)) .. '"'
end
local render_array
render_array = function(items)
  return "{" .. table.concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    for _index_0 = 1, #items do
      local item = items[_index_0]
      _accum_0[_len_0] = escape_string(item)
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)(), ", ") .. "}"
end
local render_condition
render_condition = function(value)
  if type(value) == "table" then
    return render_array(value)
  else
    return escape_string(value)
  end
end
local collect_group_lists
collect_group_lists = function(data)
  local lists = { }
  local groups = data.groups or { }
  for group_name, group_data in pairs(groups) do
    local _continue_0 = false
    repeat
      if not (type(group_data) == "table") then
        _continue_0 = true
        break
      end
      local domains = group_data.dest_domains or { }
      local cleaned = clean_domains(domains)
      if #cleaned > 0 then
        lists[group_name] = cleaned
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return lists
end
local collect_special_lists
collect_special_lists = function(data)
  local specials = { }
  local rules = data.rules or { }
  local yahoo = rules["block yahoo search"]
  if yahoo then
    local cleaned = clean_domains(yahoo.dest_domains or { })
    if #cleaned > 0 then
      specials.block_yahoo = cleaned
    end
  end
  local spotify = rules["Salon profs"]
  if spotify then
    local cleaned = clean_domains(spotify.dest_domains or { })
    if #cleaned > 0 then
      specials.spotify = cleaned
    end
  end
  return specials
end
local has_member
has_member = function(list, value)
  for _index_0 = 1, #list do
    local item = list[_index_0]
    if item == value then
      return true
    end
  end
  return false
end
local collect_macs_and_lists
collect_macs_and_lists = function(data)
  local macs = { }
  local maclists = { }
  local input_lists = data.maclists or { }
  for _index_0 = 1, #MACLIST_GROUPS do
    local name = MACLIST_GROUPS[_index_0]
    maclists[name] = { }
    local _list_0 = (input_lists[name] or { })
    for _index_1 = 1, #_list_0 do
      local member = _list_0[_index_1]
      table.insert(maclists[name], member)
    end
  end
  local users = data.users or { }
  for profile_name, profile_data in pairs(users) do
    local _continue_0 = false
    repeat
      if not (type(profile_data) == "table") then
        _continue_0 = true
        break
      end
      local group_key = PROFILE_MAP[profile_name]
      for user_key, user_data in pairs(profile_data) do
        local _continue_1 = false
        repeat
          if not (type(user_data) == "table" and user_data.devices) then
            _continue_1 = true
            break
          end
          for dev_name, dev_data in pairs(user_data.devices) do
            local _continue_2 = false
            repeat
              if not (type(dev_data) == "table") then
                _continue_2 = true
                break
              end
              local mac = dev_data.mac
              if not (mac) then
                _continue_2 = true
                break
              end
              macs[dev_name] = mac
              local target = group_key
              if user_key == "Salon profs" then
                target = "salon_profs"
              elseif user_key == "Abbés" then
                target = "abbes"
              end
              if target then
                local members = maclists[target]
                if not (has_member(members, dev_name)) then
                  table.insert(members, dev_name)
                end
              end
              _continue_2 = true
            until true
            if not _continue_2 then
              break
            end
          end
          _continue_1 = true
        until true
        if not _continue_1 then
          break
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  for _index_0 = 1, #MACLIST_GROUPS do
    local name = MACLIST_GROUPS[_index_0]
    table.sort(maclists[name])
  end
  return macs, maclists
end
local rule
rule = function(description, action, conditions)
  return {
    description = description,
    actions = {
      action
    },
    conditions = conditions or { }
  }
end
local build_rules
build_rules = function(maclists, specials)
  local rules = { }
  if specials.block_yahoo then
    rules[#rules + 1] = rule("Blocages prioritaires", "deny", {
      to_domainlist = "custom/block_yahoo"
    })
  end
  if not (#maclists.profs == 0) then
    rules[#rules + 1] = rule("Accès total Profs", "allow", {
      from_macs = maclists.profs
    })
  end
  rules[#rules + 1] = rule("Infrastructure et local", "allow", {
    to_domains = {
      "local",
      "lan",
      "home.arpa"
    }
  })
  if not (#maclists.abbes == 0) then
    rules[#rules + 1] = rule("Profil Abbés", "allow", {
      from_macs = maclists.abbes,
      to_domainlists = ABBES_LISTS
    })
  end
  if not (#maclists.eleves_limites == 0) then
    rules[#rules + 1] = rule("Profil Élèves Limités", "allow", {
      from_macs = maclists.eleves_limites,
      to_domainlists = ELEVES_LISTS
    })
  end
  if specials.spotify and #maclists.salon_profs > 0 then
    rules[#rules + 1] = rule("Spotify Salon Profs", "allow", {
      from_macs = maclists.salon_profs,
      to_domainlist = "custom/spotify"
    })
  end
  rules[#rules + 1] = rule("Verdict Final", "deny", { })
  return rules
end
local render_config
render_config = function(macs, rules)
  local lines = {
    "-- Généré par idefix2filter.moon",
    "",
    "filter:",
    '  domainlists_dir: "/etc/custos/lists"',
    '  custom_lists_dir: "/etc/custos/lists/custom"'
  }
  local mac_keys
  do
    local _accum_0 = { }
    local _len_0 = 1
    for k in pairs(macs) do
      _accum_0[_len_0] = k
      _len_0 = _len_0 + 1
    end
    mac_keys = _accum_0
  end
  table.sort(mac_keys)
  if #mac_keys > 0 then
    lines[#lines + 1] = ""
    lines[#lines + 1] = "  macs:"
    for _index_0 = 1, #mac_keys do
      local key = mac_keys[_index_0]
      lines[#lines + 1] = "    " .. tostring(escape_string(key)) .. ": " .. tostring(escape_string(macs[key]))
    end
  end
  lines[#lines + 1] = ""
  lines[#lines + 1] = "  rules: {"
  for _index_0 = 1, #rules do
    local r = rules[_index_0]
    lines[#lines + 1] = "    {"
    lines[#lines + 1] = "      description: " .. tostring(escape_string(r.description))
    lines[#lines + 1] = "      actions: " .. tostring(render_array(r.actions))
    local condition_keys
    do
      local _accum_0 = { }
      local _len_0 = 1
      for k in pairs(r.conditions) do
        _accum_0[_len_0] = k
        _len_0 = _len_0 + 1
      end
      condition_keys = _accum_0
    end
    table.sort(condition_keys)
    if #condition_keys > 0 then
      lines[#lines + 1] = "      conditions:"
      for _index_1 = 1, #condition_keys do
        local key = condition_keys[_index_1]
        lines[#lines + 1] = "        " .. tostring(key) .. ": " .. tostring(render_condition(r.conditions[key]))
      end
    else
      lines[#lines + 1] = "      conditions: {}"
    end
    lines[#lines + 1] = "    }"
  end
  lines[#lines + 1] = "  }"
  return table.concat(lines, "\n") .. "\n"
end
local convert
convert = function(data)
  local lists = collect_group_lists(data)
  local specials = collect_special_lists(data)
  local macs, maclists = collect_macs_and_lists(data)
  local rules = build_rules(maclists, specials)
  local config = render_config(macs, rules)
  return {
    lists = lists,
    specials = specials,
    macs = macs,
    maclists = maclists,
    rules = rules,
    config = config
  }
end
local sh_quote
sh_quote = function(s)
  return "'" .. (tostring(s):gsub("'", "'\\''")) .. "'"
end
local ensure_dir
ensure_dir = function(path)
  return os.execute("mkdir -p " .. tostring(sh_quote(path)))
end
local write_file
write_file = function(path, content)
  local f = assert(io.open(path, "w"))
  f:write(content)
  return f:close()
end
local write_lists
write_lists = function(cfg_dir, out)
  local base = tostring(cfg_dir) .. "/listes"
  ensure_dir(base)
  local group_names
  do
    local _accum_0 = { }
    local _len_0 = 1
    for name in pairs(out.lists) do
      _accum_0[_len_0] = name
      _len_0 = _len_0 + 1
    end
    group_names = _accum_0
  end
  table.sort(group_names)
  for _index_0 = 1, #group_names do
    local name = group_names[_index_0]
    write_file(tostring(base) .. "/" .. tostring(name) .. ".domains", (table.concat(out.lists[name], "\n")) .. "\n")
  end
  local custom = tostring(base) .. "/custom"
  ensure_dir(custom)
  local special_names
  do
    local _accum_0 = { }
    local _len_0 = 1
    for name in pairs(out.specials) do
      _accum_0[_len_0] = name
      _len_0 = _len_0 + 1
    end
    special_names = _accum_0
  end
  table.sort(special_names)
  for _index_0 = 1, #special_names do
    local name = special_names[_index_0]
    write_file(tostring(custom) .. "/" .. tostring(name) .. ".domains", (table.concat(out.specials[name], "\n")) .. "\n")
  end
end
local run
run = function(idefix_path, cfg_dir)
  local f = io.open(idefix_path, "r")
  if not (f) then
    error("impossible d'ouvrir " .. tostring(idefix_path))
  end
  local content = f:read("*a")
  f:close()
  local data = json.decode(content)
  local out = convert(data)
  ensure_dir(cfg_dir)
  write_lists(cfg_dir, out)
  write_file(tostring(cfg_dir) .. "/config.moon", out.config)
  return out
end
local main
main = function(args)
  if args == nil then
    args = arg
  end
  local idefix = args and args[1]
  local cfg = args and args[2]
  if not (idefix and cfg) then
    io.stderr:write("Usage : luajit idefix2filter.lua <idefix.json> <dossier-sortie>\n")
    os.exit(1)
  end
  run(idefix, cfg)
  return io.write("Configuration écrite dans " .. tostring(cfg) .. "/config.moon\n")
end
local script_name = arg and arg[0] or ""
if script_name:match("idefix2filter") then
  main()
end
return {
  clean_domain = clean_domain,
  clean_domains = clean_domains,
  collect_group_lists = collect_group_lists,
  collect_special_lists = collect_special_lists,
  collect_macs_and_lists = collect_macs_and_lists,
  build_rules = build_rules,
  render_config = render_config,
  convert = convert,
  write_lists = write_lists,
  run = run,
  main = main
}
