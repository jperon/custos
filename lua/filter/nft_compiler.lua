local bit = require("bit")
local is_array
is_array = function(t)
  if not (type(t) == "table") then
    return false
  end
  local n = #t
  if n == 0 then
    return false
  end
  for i = 1, n do
    if t[i] == nil then
      return false
    end
  end
  return true
end
local as_list
as_list = function(v)
  if v == nil then
    return { }
  end
  if type(v) == "table" and is_array(v) then
    return v
  end
  return {
    v
  }
end
local sorted_keys
sorted_keys = function(t)
  local keys
  do
    local _accum_0 = { }
    local _len_0 = 1
    for k in pairs(t) do
      _accum_0[_len_0] = k
      _len_0 = _len_0 + 1
    end
    keys = _accum_0
  end
  table.sort(keys, function(a, b)
    return tostring(a) < tostring(b)
  end)
  return keys
end
local serialize_stable
serialize_stable = function(v)
  local tv = type(v)
  if tv == "nil" then
    return "null"
  end
  if tv == "boolean" or tv == "number" then
    return tostring(v)
  end
  if tv == "string" then
    return string.format("%q", v)
  end
  if not (tv == "table") then
    return string.format("%q", tostring(v))
  end
  if is_array(v) then
    local parts
    do
      local _accum_0 = { }
      local _len_0 = 1
      for _index_0 = 1, #v do
        local item = v[_index_0]
        _accum_0[_len_0] = serialize_stable(item)
        _len_0 = _len_0 + 1
      end
      parts = _accum_0
    end
    return "[" .. table.concat(parts, ",") .. "]"
  end
  local keys = sorted_keys(v)
  local parts = { }
  for _, k in ipairs(keys) do
    parts[#parts + 1] = tostring(serialize_stable(k)) .. ":" .. tostring(serialize_stable(v[k]))
  end
  return "{" .. table.concat(parts, ",") .. "}"
end
local fnv1a32_hex
fnv1a32_hex = function(s)
  local hash = 2166136261
  for i = 1, #s do
    hash = bit.bxor(hash, s:byte(i))
    hash = (hash * 16777619) % 4294967296
  end
  return string.format("%08x", hash)
end
local sanitize_id
sanitize_id = function(raw)
  local s = tostring(raw or ""):lower()
  s = s:gsub("[^a-z0-9_%-]+", "_")
  s = s:gsub("_+", "_")
  s = s:gsub("^_+", "")
  s = s:gsub("_+$", "")
  s = s:gsub("%-+", "_")
  if #s == 0 then
    s = "rule"
  end
  if #s > 40 then
    s = s:sub(1, 40)
  end
  return s
end
local stable_rule_id
stable_rule_id = function(rule, idx, used)
  local explicit = rule.rule_id
  local base = nil
  if explicit and tostring(explicit):match("%S") then
    base = sanitize_id(explicit)
  else
    local canonical = serialize_stable({
      description = rule.description or "",
      conditions = rule.conditions or { },
      actions = rule.actions or { },
      network = rule.network or { }
    })
    base = "r_" .. fnv1a32_hex(canonical)
  end
  local rid = base
  local n = 1
  while used[rid] do
    n = n + 1
    rid = tostring(base) .. "_" .. tostring(n)
  end
  used[rid] = true
  return rid
end
local append_unique
append_unique = function(dst, seen, val)
  if not (val and tostring(val):match("%S")) then
    return 
  end
  local key = tostring(val)
  if seen[key] then
    return 
  end
  seen[key] = true
  dst[#dst + 1] = key
end
local collect_nets
collect_nets = function(cfg, rule)
  local v4, v6 = { }, { }
  local seen4, seen6 = { }, { }
  local named = cfg.nets or { }
  local add_net
  add_net = function(raw)
    if not (raw) then
      return 
    end
    local net = tostring(raw):match("^%s*(.-)%s*$")
    if not (net and #net > 0) then
      return 
    end
    if net:find(":", 1, true) then
      return append_unique(v6, seen6, net)
    else
      return append_unique(v4, seen4, net)
    end
  end
  local add_named
  add_named = function(list_name)
    if not (list_name) then
      return 
    end
    local nets = named[list_name] or { }
    for _, n in ipairs(as_list(nets)) do
      add_net(n)
    end
  end
  for _, cond in ipairs(rule.conditions or { }) do
    local _continue_0 = false
    repeat
      if not (type(cond) == "table") then
        _continue_0 = true
        break
      end
      for k, args in pairs(cond) do
        if k == "from_net" then
          add_net(args)
        elseif k == "from_nets" then
          for _, n in ipairs(as_list(args)) do
            add_net(n)
          end
        elseif k == "from_netlist" then
          add_named(args)
        elseif k == "from_netlists" then
          for _, list_name in ipairs(as_list(args)) do
            add_named(list_name)
          end
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  table.sort(v4)
  table.sort(v6)
  return v4, v6
end
local collect_subnets
collect_subnets = function(rule)
  local v4, v6 = { }, { }
  local seen4, seen6 = { }, { }
  local add_subnet
  add_subnet = function(cidr_str)
    if not (cidr_str) then
      return 
    end
    local net = tostring(cidr_str):match("^%s*(.-)%s*$")
    if not (net and #net > 0) then
      return 
    end
    if net:find(":", 1, true) then
      return append_unique(v6, seen6, net)
    else
      return append_unique(v4, seen4, net)
    end
  end
  for _, cond in ipairs(rule.conditions or { }) do
    local _continue_0 = false
    repeat
      if not (type(cond) == "table") then
        _continue_0 = true
        break
      end
      for k, args in pairs(cond) do
        if k == "from_subnet" then
          if type(args) == "string" then
            add_subnet(args)
          elseif type(args) == "table" and args.net then
            add_subnet(args.net)
          end
        elseif k == "from_subnets" then
          for _, subnet_spec in ipairs(as_list(args)) do
            if type(subnet_spec) == "string" then
              add_subnet(subnet_spec)
            elseif type(subnet_spec) == "table" and subnet_spec.net then
              add_subnet(subnet_spec.net)
            end
          end
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  table.sort(v4)
  table.sort(v6)
  return v4, v6
end
local collect_times
collect_times = function(rule)
  local out = { }
  local seen = { }
  for _, cond in ipairs(rule.conditions or { }) do
    local _continue_0 = false
    repeat
      if not (type(cond) == "table") then
        _continue_0 = true
        break
      end
      for k, args in pairs(cond) do
        if k == "in_time" then
          append_unique(out, seen, args)
        elseif k == "in_times" then
          for _, t in ipairs(as_list(args)) do
            append_unique(out, seen, t)
          end
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  table.sort(out)
  return out
end
local collect_dns
collect_dns = function(rule)
  local refs = { }
  local seen = { }
  local dns_keys = {
    to_domain = true,
    to_domains = true,
    to_domainlist = true,
    to_domainlists = true
  }
  for _, cond in ipairs(rule.conditions or { }) do
    local _continue_0 = false
    repeat
      if not (type(cond) == "table") then
        _continue_0 = true
        break
      end
      for k, args in pairs(cond) do
        if dns_keys[k] then
          if k == "to_domain" or k == "to_domainlist" then
            append_unique(refs, seen, tostring(k) .. ":" .. tostring(tostring(args)))
          else
            for _, v in ipairs(as_list(args)) do
              append_unique(refs, seen, tostring(k) .. ":" .. tostring(tostring(v)))
            end
          end
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  table.sort(refs)
  return refs
end
local normalize_proto
normalize_proto = function(p)
  local v = tostring(p):lower()
  if v == "tcp" or v == "udp" or v == "icmp" or v == "icmpv6" then
    return v
  end
  return nil
end
local collect_proto_ports
collect_proto_ports = function(rule)
  local net = rule.network or { }
  local protos = { }
  local seen_proto = { }
  local ports = { }
  local seen_port = { }
  local proto_src = net.proto or net.protocol or net.protocols
  for _, p in ipairs(as_list(proto_src)) do
    local n = normalize_proto(p)
    if n then
      append_unique(protos, seen_proto, n)
    end
  end
  local port_src = net.ports or net.dports or net.dest_ports
  for _, p in ipairs(as_list(port_src)) do
    local _continue_0 = false
    repeat
      local raw = tostring(p):match("^%s*(.-)%s*$")
      if not (raw and #raw > 0) then
        _continue_0 = true
        break
      end
      if raw:match("^%d+$") then
        append_unique(ports, seen_port, raw)
      else
        local from_s, to_s = raw:match("^(%d+)%-(%d+)$")
        if from_s and to_s then
          append_unique(ports, seen_port, tostring(tonumber(from_s)) .. "-" .. tostring(tonumber(to_s)))
        end
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  table.sort(protos)
  table.sort(ports)
  return protos, ports
end
local resolve_action
resolve_action = function(rule)
  for _, action in ipairs(rule.actions or { }) do
    if action == "allow" or action == "deny" or action == "dnsonly" then
      return action
    end
  end
  return nil
end
local build_rule
build_rule = function(cfg, rule, idx, used_ids)
  local rid = stable_rule_id(rule, idx, used_ids)
  local src4, src6 = collect_nets(cfg, rule)
  local subnet4, subnet6 = collect_subnets(rule)
  local times = collect_times(rule)
  local dns_refs = collect_dns(rule)
  local protos, ports = collect_proto_ports(rule)
  local action = resolve_action(rule)
  local chain = "cv_rule_" .. rid
  local mark = string.format("0x%x", 0x4000 + idx)
  return {
    index = idx,
    rule_id = rid,
    description = rule.description or rid,
    action = action or "allow",
    dns_scope = #dns_refs > 0,
    dns_refs = dns_refs,
    time_ranges = times,
    source_ipv4 = src4,
    source_ipv6 = src6,
    subnet_ipv4 = subnet4,
    subnet_ipv6 = subnet6,
    protocols = protos,
    ports = ports,
    chain = chain,
    mark = mark,
    set_src4 = #src4 > 0 and tostring(chain) .. "_src4" or nil,
    set_src6 = #src6 > 0 and tostring(chain) .. "_src6" or nil,
    set_subnet4 = #subnet4 > 0 and tostring(chain) .. "_subnet4" or nil,
    set_subnet6 = #subnet6 > 0 and tostring(chain) .. "_subnet6" or nil,
    set_ports = #ports > 0 and tostring(chain) .. "_dports" or nil,
    stubs = {
      time_match = #times > 0,
      dns_match = #dns_refs > 0
    }
  }
end
local compile
compile = function(filter_cfg)
  local cfg = filter_cfg or { }
  local rules_cfg = cfg.rules or { }
  local decision = cfg.decision or { }
  local first_match_wins
  if decision.first_match_wins == nil then
    first_match_wins = true
  else
    first_match_wins = not not decision.first_match_wins
  end
  local used_ids = { }
  local rules
  do
    local _accum_0 = { }
    local _len_0 = 1
    for idx, rule in ipairs(rules_cfg) do
      _accum_0[_len_0] = build_rule(cfg, rule, idx, used_ids)
      _len_0 = _len_0 + 1
    end
    rules = _accum_0
  end
  local action_map = { }
  local rules_by_id = { }
  for _, r in ipairs(rules) do
    local verdict
    if r.action == "deny" then
      verdict = "drop"
    else
      verdict = "accept"
    end
    action_map[#action_map + 1] = {
      mark = r.mark,
      verdict = verdict,
      rule_id = r.rule_id,
      action = r.action
    }
    rules_by_id[r.rule_id] = r
  end
  return {
    first_match_wins = first_match_wins,
    dispatch_chain = "cv_rules_dispatch",
    action_vmap = "cv_rule_action_vmap",
    rules = rules,
    rules_by_id = rules_by_id,
    action_map = action_map
  }
end
local render_set
render_set = function(name, set_type, flags, elems, indent, include_elems)
  if include_elems == nil then
    include_elems = true
  end
  local lines = { }
  lines[#lines + 1] = tostring(indent) .. "set " .. tostring(name) .. " {"
  lines[#lines + 1] = tostring(indent) .. "  type " .. tostring(set_type)
  if flags and #flags > 0 then
    lines[#lines + 1] = tostring(indent) .. "  flags " .. tostring(flags)
  end
  if include_elems and elems and #elems > 0 then
    lines[#lines + 1] = tostring(indent) .. "  elements = { " .. tostring(table.concat(elems, ", ")) .. " }"
  end
  lines[#lines + 1] = tostring(indent) .. "}"
  return lines
end
local match_exprs
match_exprs = function(rule)
  local l4 = { }
  if #rule.protocols > 0 then
    l4[#l4 + 1] = "meta l4proto { " .. tostring(table.concat(rule.protocols, ", ")) .. " }"
  end
  if rule.set_ports then
    l4[#l4 + 1] = "th dport @" .. tostring(rule.set_ports)
  end
  local base = table.concat(l4, " ")
  local exprs = { }
  if rule.set_src4 or rule.set_subnet4 then
    local expr_parts = {
      "ip saddr"
    }
    if rule.set_src4 and rule.set_subnet4 then
      expr_parts[#expr_parts + 1] = "{ @" .. tostring(rule.set_src4) .. ", @" .. tostring(rule.set_subnet4) .. " }"
    elseif rule.set_src4 then
      expr_parts[#expr_parts + 1] = "@" .. tostring(rule.set_src4)
    else
      expr_parts[#expr_parts + 1] = "@" .. tostring(rule.set_subnet4)
    end
    local ipv4_match = table.concat(expr_parts, " ")
    exprs[#exprs + 1] = table.concat({
      ipv4_match,
      base
    }, " "):gsub("%s+", " ")
  end
  if rule.set_src6 or rule.set_subnet6 then
    local expr_parts = {
      "ip6 saddr"
    }
    if rule.set_src6 and rule.set_subnet6 then
      expr_parts[#expr_parts + 1] = "{ @" .. tostring(rule.set_src6) .. ", @" .. tostring(rule.set_subnet6) .. " }"
    elseif rule.set_src6 then
      expr_parts[#expr_parts + 1] = "@" .. tostring(rule.set_src6)
    else
      expr_parts[#expr_parts + 1] = "@" .. tostring(rule.set_subnet6)
    end
    local ipv6_match = table.concat(expr_parts, " ")
    exprs[#exprs + 1] = table.concat({
      ipv6_match,
      base
    }, " "):gsub("%s+", " ")
  end
  if #exprs == 0 then
    exprs[1] = base
  end
  return exprs
end
local render_rule_chain
render_rule_chain = function(rule, indent)
  local lines = { }
  lines[#lines + 1] = tostring(indent) .. "chain " .. tostring(rule.chain) .. " {"
  lines[#lines + 1] = tostring(indent) .. "  comment \"custos rule_id=" .. tostring(rule.rule_id) .. " action=" .. tostring(rule.action) .. "\""
  lines[#lines + 1] = tostring(indent) .. "  counter comment \"dns_scope=" .. tostring(rule.dns_scope and 'yes' or 'no') .. "\""
  if rule.stubs.time_match then
    lines[#lines + 1] = tostring(indent) .. "  counter comment \"stub:time_ranges=" .. tostring(table.concat(rule.time_ranges, ',')) .. "\""
  end
  for _, expr in ipairs(match_exprs(rule)) do
    local e = expr:match("^%s*(.-)%s*$")
    if e and #e > 0 then
      lines[#lines + 1] = tostring(indent) .. "  " .. tostring(e) .. " meta mark set " .. tostring(rule.mark) .. " counter return comment \"rule_id=" .. tostring(rule.rule_id) .. "\""
    else
      lines[#lines + 1] = tostring(indent) .. "  meta mark set " .. tostring(rule.mark) .. " counter return comment \"rule_id=" .. tostring(rule.rule_id) .. "\""
    end
  end
  lines[#lines + 1] = tostring(indent) .. "  return"
  lines[#lines + 1] = tostring(indent) .. "}"
  return lines
end
local render
render = function(plan, indent, include_elements)
  if indent == nil then
    indent = "  "
  end
  if include_elements == nil then
    include_elements = true
  end
  if not (plan and plan.rules and #plan.rules > 0) then
    return tostring(indent) .. "# b2: no compiled rule objects\n"
  end
  local lines = { }
  lines[#lines + 1] = tostring(indent) .. "# ── b2: compiled per-rule nft objects (staging for c1/c2) ──"
  lines[#lines + 1] = tostring(indent) .. "# first_match_wins=" .. tostring(plan.first_match_wins and 'true' or 'false')
  lines[#lines + 1] = tostring(indent) .. "map " .. tostring(plan.action_vmap) .. " {"
  lines[#lines + 1] = tostring(indent) .. "  type mark : verdict"
  local entries
  do
    local _accum_0 = { }
    local _len_0 = 1
    local _list_0 = plan.action_map
    for _index_0 = 1, #_list_0 do
      local e = _list_0[_index_0]
      _accum_0[_len_0] = tostring(e.mark) .. " : " .. tostring(e.verdict)
      _len_0 = _len_0 + 1
    end
    entries = _accum_0
  end
  lines[#lines + 1] = tostring(indent) .. "  elements = { " .. tostring(table.concat(entries, ', ')) .. " }"
  lines[#lines + 1] = tostring(indent) .. "}"
  for _, rule in ipairs(plan.rules) do
    if rule.set_src4 then
      for _, l in ipairs(render_set(rule.set_src4, "ipv4_addr", "interval", rule.source_ipv4, indent, include_elements)) do
        lines[#lines + 1] = l
      end
    end
    if rule.set_src6 then
      for _, l in ipairs(render_set(rule.set_src6, "ipv6_addr", "interval", rule.source_ipv6, indent, include_elements)) do
        lines[#lines + 1] = l
      end
    end
    if rule.set_subnet4 then
      for _, l in ipairs(render_set(rule.set_subnet4, "ipv4_addr", "interval", rule.subnet_ipv4, indent, include_elements)) do
        lines[#lines + 1] = l
      end
    end
    if rule.set_subnet6 then
      for _, l in ipairs(render_set(rule.set_subnet6, "ipv6_addr", "interval", rule.subnet_ipv6, indent, include_elements)) do
        lines[#lines + 1] = l
      end
    end
    if rule.set_ports then
      for _, l in ipairs(render_set(rule.set_ports, "inet_service", "", rule.ports, indent, include_elements)) do
        lines[#lines + 1] = l
      end
    end
    for _, l in ipairs(render_rule_chain(rule, indent)) do
      lines[#lines + 1] = l
    end
  end
  lines[#lines + 1] = tostring(indent) .. "chain " .. tostring(plan.dispatch_chain) .. " {"
  lines[#lines + 1] = tostring(indent) .. "  comment \"b2 dispatch skeleton (not hooked before c1/c2)\""
  for _, rule in ipairs(plan.rules) do
    lines[#lines + 1] = tostring(indent) .. "  jump " .. tostring(rule.chain) .. " comment \"idx=" .. tostring(rule.index) .. " rule_id=" .. tostring(rule.rule_id) .. "\""
    if plan.first_match_wins then
      lines[#lines + 1] = tostring(indent) .. "  meta mark != 0x0 return comment \"first_match_wins\""
    end
  end
  lines[#lines + 1] = tostring(indent) .. "  return"
  lines[#lines + 1] = tostring(indent) .. "}"
  return table.concat(lines, "\n") .. "\n"
end
return {
  compile = compile,
  render = render,
  serialize_stable = serialize_stable
}
