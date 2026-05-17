local compiler_api = require("filter.compiler_api")
local sanitize_ascii = compiler_api.sanitize_ascii
local sanitize_id = compiler_api.sanitize_id
local NFT_COMMENT_MAX = 128
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
local rule_id = require("filter.rule_id")
local stable_rule_id = rule_id.generate_unique
local nft_comment
nft_comment = function(text)
  local s = sanitize_ascii(text)
  if #s > NFT_COMMENT_MAX then
    return s:sub(1, NFT_COMMENT_MAX)
  else
    return s
  end
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
  for k, args in pairs(rule.conditions or { }) do
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
  table.sort(v4)
  table.sort(v6)
  return v4, v6
end
local collect_dest_nets
collect_dest_nets = function(cfg, rule)
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
  for k, args in pairs(rule.conditions or { }) do
    if k == "to_net" then
      add_net(args)
    elseif k == "to_nets" then
      for _, n in ipairs(as_list(args)) do
        add_net(n)
      end
    elseif k == "to_netlist" then
      add_named(args)
    elseif k == "to_netlists" then
      for _, list_name in ipairs(as_list(args)) do
        add_named(list_name)
      end
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
  for k, args in pairs(rule.conditions or { }) do
    if k == "from_subnet" then
      if type(args) == "string" then
        add_subnet(args)
      elseif type(args) == "table" then
        for _, s in ipairs(as_list(args)) do
          add_subnet(s)
        end
      end
    elseif k == "from_subnets" then
      for _, s in ipairs(as_list(args)) do
        if type(s) == "string" then
          add_subnet(s)
        elseif type(s) == "table" and s.net then
          add_subnet(s.net)
        end
      end
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
  for k, args in pairs(rule.conditions or { }) do
    if k == "in_time" then
      append_unique(out, seen, args)
    elseif k == "in_times" then
      for _, t in ipairs(as_list(args)) do
        append_unique(out, seen, t)
      end
    elseif k == "in_timelist" then
      append_unique(out, seen, args)
    elseif k == "in_timelists" then
      for _, list_name in ipairs(as_list(args)) do
        append_unique(out, seen, list_name)
      end
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
  for k, args in pairs(rule.conditions or { }) do
    if dns_keys[k] then
      if k == "to_domain" or k == "to_domainlist" then
        append_unique(refs, seen, tostring(k) .. ":" .. tostring(tostring(args)))
      elseif k == "to_domains" or k == "to_domainlists" then
        for _, d in ipairs(as_list(args)) do
          append_unique(refs, seen, tostring(k) .. ":" .. tostring(tostring(d)))
        end
      end
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
build_rule = function(cfg, rule, idx, used_ids, metadata_rule_id)
  if metadata_rule_id == nil then
    metadata_rule_id = nil
  end
  local rid = metadata_rule_id or stable_rule_id(rule, idx, used_ids)
  local src4, src6 = collect_nets(cfg, rule)
  local dst4, dst6 = collect_dest_nets(cfg, rule)
  local subnet4, subnet6 = collect_subnets(rule)
  local times = collect_times(rule)
  local dns_refs = collect_dns(rule)
  local protos, ports = collect_proto_ports(rule)
  local action = resolve_action(rule)
  local chain = "cv_rule_" .. rid
  local mark = string.format("0x%x", 0x4000 + idx)
  local requires_auth = false
  for k, _ in pairs(rule.conditions or { }) do
    if k == "from_users" or k == "from_userlists" then
      requires_auth = true
      break
    end
  end
  return {
    index = idx,
    rule_id = rid,
    description = rule.description or rid,
    action = action or "allow",
    dns_scope = #dns_refs > 0 or requires_auth,
    dns_refs = dns_refs,
    time_ranges = times,
    source_ipv4 = src4,
    source_ipv6 = src6,
    dest_ipv4 = dst4,
    dest_ipv6 = dst6,
    subnet_ipv4 = subnet4,
    subnet_ipv6 = subnet6,
    protocols = protos,
    ports = ports,
    chain = chain,
    mark = mark,
    requires_auth = requires_auth,
    set_src4 = #src4 > 0 and tostring(chain) .. "_src4" or nil,
    set_src6 = #src6 > 0 and tostring(chain) .. "_src6" or nil,
    set_dst4 = #dst4 > 0 and tostring(chain) .. "_dst4" or nil,
    set_dst6 = #dst6 > 0 and tostring(chain) .. "_dst6" or nil,
    set_subnet4 = #subnet4 > 0 and tostring(chain) .. "_subnet4" or nil,
    set_subnet6 = #subnet6 > 0 and tostring(chain) .. "_subnet6" or nil,
    set_ports = #ports > 0 and tostring(chain) .. "_dports" or nil,
    set_dyn_ip4 = tostring(rid) .. "_ip4",
    set_dyn_ip6 = tostring(rid) .. "_ip6",
    set_dyn_mac4 = tostring(rid) .. "_mac4",
    set_dyn_mac6 = tostring(rid) .. "_mac6",
    set_auth_mac = requires_auth and tostring(rid) .. "_auth_mac" or nil,
    set_auth_ip4 = requires_auth and tostring(rid) .. "_auth_ip4" or nil,
    set_auth_ip6 = requires_auth and tostring(rid) .. "_auth_ip6" or nil,
    stubs = {
      time_match = #times > 0,
      dns_match = #dns_refs > 0
    }
  }
end
local compile
compile = function(filter_cfg, rules_metadata)
  if rules_metadata == nil then
    rules_metadata = nil
  end
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
      local meta_rid = rules_metadata and rules_metadata[idx] and rules_metadata[idx].rule_id
      local _value_0 = build_rule(cfg, rule, idx, used_ids, meta_rid)
      _accum_0[_len_0] = _value_0
      _len_0 = _len_0 + 1
    end
    rules = _accum_0
  end
  local action_map = { }
  local rules_by_id = { }
  local metrics = {
    total_rules = #rules,
    nft_compilable = 0,
    worker_only = 0,
    conditions_compiled = 0,
    conditions_worker_only = 0
  }
  local plan_rules = { }
  local all_rules = { }
  for idx, r in ipairs(rules) do
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
    all_rules[#all_rules + 1] = r
    if rules_metadata and rules_metadata[idx] then
      r.conditions_meta = rules_metadata[idx].conditions
      r.actions_meta = rules_metadata[idx].actions
      r.worker_only = rules_metadata[idx].worker_only
    end
    local is_worker_only = r.worker_only or (rules_metadata and rules_metadata[idx] and rules_metadata[idx].worker_only)
    if is_worker_only then
      metrics.worker_only = metrics.worker_only + 1
    else
      metrics.nft_compilable = metrics.nft_compilable + 1
    end
    local conditions_meta = r.conditions_meta or (rules_metadata and rules_metadata[idx] and rules_metadata[idx].conditions)
    if conditions_meta then
      local first_elem = conditions_meta[1]
      local is_flat_format = first_elem and first_elem.name and first_elem.args
      if is_flat_format then
        for _, cond_meta in ipairs(conditions_meta) do
          if cond_meta.name == "from_user" or cond_meta.name == "from_users" or cond_meta.name == "from_userlist" or cond_meta.name == "from_userlists" then
            r.requires_auth = true
            break
          end
        end
      end
    end
    if r.requires_auth then
      if not (r.set_auth_mac) then
        r.set_auth_mac = tostring(r.rule_id) .. "_auth_mac"
      end
      if not (r.set_auth_ip4) then
        r.set_auth_ip4 = tostring(r.rule_id) .. "_auth_ip4"
      end
      if not (r.set_auth_ip6) then
        r.set_auth_ip6 = tostring(r.rule_id) .. "_auth_ip6"
      end
    end
    if rules_metadata and rules_metadata[idx] and rules_metadata[idx].conditions then
      for _, cond in ipairs(rules_metadata[idx].conditions) do
        if cond.capabilities and cond.capabilities.nft then
          metrics.conditions_compiled = metrics.conditions_compiled + 1
        else
          metrics.conditions_worker_only = metrics.conditions_worker_only + 1
        end
      end
    end
    local has_nft_cond = false
    if conditions_meta then
      local first_elem = conditions_meta[1]
      local is_flat_format = first_elem and first_elem.name and first_elem.args
      if is_flat_format then
        for _, cond_meta in ipairs(conditions_meta) do
          if cond_meta.capabilities and cond_meta.capabilities.nft then
            has_nft_cond = true
            break
          end
        end
      end
    end
    local include_rule = (has_nft_cond and not is_worker_only) or r.requires_auth or (r.set_dyn_ip4 or r.set_dyn_ip6 or r.set_dyn_mac4 or r.set_dyn_mac6)
    if include_rule then
      plan_rules[#plan_rules + 1] = r
    end
  end
  return {
    first_match_wins = first_match_wins,
    dispatch_chain = "cv_rules_dispatch",
    action_vmap = "cv_rule_action_vmap",
    rules = plan_rules,
    all_rules = all_rules,
    rules_by_id = rules_by_id,
    action_map = action_map,
    rules_metadata = rules_metadata,
    metrics = metrics
  }
end
local render_set
render_set = function(name, set_type, flags, elems, indent, include_elements)
  if include_elements == nil then
    include_elements = true
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
local compile_conditions_nft
compile_conditions_nft = function(conditions_meta, family)
  if not (conditions_meta and #conditions_meta > 0) then
    return { }
  end
  local exprs = { }
  for _, cond_meta in ipairs(conditions_meta) do
    local _continue_0 = false
    repeat
      if not (cond_meta.capabilities) then
        _continue_0 = true
        break
      end
      if not (cond_meta.capabilities.nft) then
        _continue_0 = true
        break
      end
      if cond_meta.compile_nft then
        local expr, err = cond_meta.compile_nft(family)
        if expr then
          exprs[#exprs + 1] = expr
        else
          if family == "inet" then
            local expr_ip, err_ip = cond_meta.compile_nft("ip")
            if expr_ip then
              exprs[#exprs + 1] = expr_ip
            end
            local expr_ip6, err_ip6 = cond_meta.compile_nft("ip6")
            if expr_ip6 then
              exprs[#exprs + 1] = expr_ip6
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
  return exprs
end
local compile_action_nft
compile_action_nft = function(actions_meta)
  if not (actions_meta and #actions_meta > 0) then
    return nil
  end
  for _, act_meta in ipairs(actions_meta) do
    if act_meta.capabilities and act_meta.capabilities.nft then
      if act_meta.compile_nft then
        local verdict
        verdict, _ = act_meta.compile_nft()
        if verdict then
          return verdict
        end
      end
    end
  end
  return nil
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
  if rule.conditions_meta then
    local first_elem = rule.conditions_meta[1]
    local is_flat_format = first_elem and first_elem.name and first_elem.args
    local group_exprs = { }
    if is_flat_format then
      local compiled_exprs = compile_conditions_nft(rule.conditions_meta, "inet")
      if #compiled_exprs > 0 then
        local combined = table.concat(compiled_exprs, " ")
        group_exprs[#group_exprs + 1] = combined
      end
    end
    if #group_exprs > 0 then
      local exprs = { }
      for _index_0 = 1, #group_exprs do
        local group_expr = group_exprs[_index_0]
        local full_expr = table.concat({
          group_expr,
          base
        }, " "):gsub("%s+", " ")
        exprs[#exprs + 1] = full_expr
      end
      return exprs
    end
  end
  local exprs = { }
  if rule.set_src4 or rule.set_subnet4 or rule.set_dst4 then
    local parts = { }
    if rule.set_src4 or rule.set_subnet4 then
      local src_parts = {
        "ip saddr"
      }
      if rule.set_src4 and rule.set_subnet4 then
        src_parts[#src_parts + 1] = "{ @" .. tostring(rule.set_src4) .. ", @" .. tostring(rule.set_subnet4) .. " }"
      elseif rule.set_src4 then
        src_parts[#src_parts + 1] = "@" .. tostring(rule.set_src4)
      else
        src_parts[#src_parts + 1] = "@" .. tostring(rule.set_subnet4)
      end
      parts[#parts + 1] = table.concat(src_parts, " ")
    end
    if rule.set_dst4 then
      parts[#parts + 1] = "ip daddr @" .. tostring(rule.set_dst4)
    end
    if #parts > 0 then
      local ipv4_match = table.concat(parts, " ")
      exprs[#exprs + 1] = table.concat({
        ipv4_match,
        base
      }, " "):gsub("%s+", " ")
    end
  end
  if rule.set_src6 or rule.set_subnet6 or rule.set_dst6 then
    local parts = { }
    if rule.set_src6 or rule.set_subnet6 then
      local src_parts = {
        "ip6 saddr"
      }
      if rule.set_src6 and rule.set_subnet6 then
        src_parts[#src_parts + 1] = "{ @" .. tostring(rule.set_src6) .. ", @" .. tostring(rule.set_subnet6) .. " }"
      elseif rule.set_src6 then
        src_parts[#src_parts + 1] = "@" .. tostring(rule.set_src6)
      else
        src_parts[#src_parts + 1] = "@" .. tostring(rule.set_subnet6)
      end
      parts[#parts + 1] = table.concat(src_parts, " ")
    end
    if rule.set_dst6 then
      parts[#parts + 1] = "ip6 daddr @" .. tostring(rule.set_dst6)
    end
    if #parts > 0 then
      local ipv6_match = table.concat(parts, " ")
      exprs[#exprs + 1] = table.concat({
        ipv6_match,
        base
      }, " "):gsub("%s+", " ")
    end
  end
  if rule.set_dyn_mac6 then
    exprs[#exprs + 1] = ("ether saddr . ip6 daddr @" .. tostring(rule.set_dyn_mac6) .. " " .. tostring(base)):gsub("%s+", " ")
  end
  if rule.set_dyn_mac4 then
    exprs[#exprs + 1] = ("ether saddr . ip daddr @" .. tostring(rule.set_dyn_mac4) .. " " .. tostring(base)):gsub("%s+", " ")
  end
  if rule.set_dyn_ip6 then
    exprs[#exprs + 1] = ("ip6 saddr . ip6 daddr @" .. tostring(rule.set_dyn_ip6) .. " " .. tostring(base)):gsub("%s+", " ")
  end
  if rule.set_dyn_ip4 then
    exprs[#exprs + 1] = ("ip saddr . ip daddr @" .. tostring(rule.set_dyn_ip4) .. " " .. tostring(base)):gsub("%s+", " ")
  end
  if #exprs == 0 then
    exprs[1] = base
  end
  return exprs
end
local dynamic_match_exprs
dynamic_match_exprs = function(rule, force)
  if force == nil then
    force = false
  end
  if not ((rule.dns_scope and rule.action ~= "dnsonly") or force) then
    return { }
  end
  local l4 = { }
  if #rule.protocols > 0 then
    l4[#l4 + 1] = "meta l4proto { " .. tostring(table.concat(rule.protocols, ", ")) .. " }"
  end
  if rule.set_ports then
    l4[#l4 + 1] = "th dport @" .. tostring(rule.set_ports)
  end
  local base = table.concat(l4, " ")
  local parts = {
    "ether saddr . ip6 daddr @" .. tostring(rule.set_dyn_mac6),
    "ether saddr . ip daddr @" .. tostring(rule.set_dyn_mac4),
    "ip6 saddr . ip6 daddr @" .. tostring(rule.set_dyn_ip6),
    "ip saddr . ip daddr @" .. tostring(rule.set_dyn_ip4)
  }
  local out = { }
  for _, p in ipairs(parts) do
    out[#out + 1] = table.concat({
      p,
      base
    }, " "):gsub("%s+", " ")
  end
  return out
end
local render_rule_chain
render_rule_chain = function(rule, indent)
  local lines = { }
  lines[#lines + 1] = tostring(indent) .. "chain " .. tostring(rule.chain) .. " {"
  lines[#lines + 1] = tostring(indent) .. "  comment \"" .. tostring(nft_comment("custos rule_id=" .. tostring(rule.rule_id) .. " action=" .. tostring(rule.action))) .. "\""
  lines[#lines + 1] = tostring(indent) .. "  counter comment \"dns_scope=" .. tostring(rule.dns_scope and 'yes' or 'no') .. "\""
  if rule.stubs.time_match then
    lines[#lines + 1] = tostring(indent) .. "  counter comment \"stub:time_ranges=" .. tostring(table.concat(rule.time_ranges, ',')) .. "\""
  end
  local verdict
  if rule.action == "deny" then
    verdict = "drop"
  else
    verdict = "accept"
  end
  if rule.requires_auth then
    local auth_chain = tostring(rule.chain) .. "_auth"
    local auth_mark = "0x00010000"
    lines[#lines + 1] = tostring(indent) .. "  meta mark set 0x00000000 comment \"reset VLAN and auth marks\""
    lines[#lines + 1] = tostring(indent) .. "  jump " .. tostring(auth_chain) .. " comment \"check authentication\""
    lines[#lines + 1] = tostring(indent) .. "  meta mark != " .. tostring(auth_mark) .. " return comment \"no auth match\""
  end
  if rule.worker_only and rule.requires_auth then
    local all_exprs = { }
    for _, expr in ipairs(dynamic_match_exprs(rule, true)) do
      all_exprs[#all_exprs + 1] = expr
    end
    for _, expr in ipairs(all_exprs) do
      local e = expr:match("^%s*(.-)%s*$")
      if e and #e > 0 then
        lines[#lines + 1] = tostring(indent) .. "  " .. tostring(e) .. " meta mark set " .. tostring(rule.mark) .. " counter " .. tostring(verdict) .. " comment \"" .. tostring(nft_comment("rule_id=" .. tostring(rule.rule_id) .. " worker-only auth dynamic")) .. "\""
      end
    end
    lines[#lines + 1] = tostring(indent) .. "  return"
  elseif rule.worker_only then
    local all_exprs = { }
    for _, expr in ipairs(dynamic_match_exprs(rule, true)) do
      all_exprs[#all_exprs + 1] = expr
    end
    for _, expr in ipairs(all_exprs) do
      local e = expr:match("^%s*(.-)%s*$")
      if e and #e > 0 then
        lines[#lines + 1] = tostring(indent) .. "  " .. tostring(e) .. " meta mark set " .. tostring(rule.mark) .. " counter " .. tostring(verdict) .. " comment \"" .. tostring(nft_comment("rule_id=" .. tostring(rule.rule_id) .. " worker-only dynamic")) .. "\""
      end
    end
    lines[#lines + 1] = tostring(indent) .. "  return"
  else
    local all_exprs = { }
    for _, expr in ipairs(dynamic_match_exprs(rule)) do
      all_exprs[#all_exprs + 1] = expr
    end
    if not (rule.dns_scope) then
      for _, expr in ipairs(match_exprs(rule)) do
        all_exprs[#all_exprs + 1] = expr
      end
    end
    for _, expr in ipairs(all_exprs) do
      local e = expr:match("^%s*(.-)%s*$")
      if e and #e > 0 then
        lines[#lines + 1] = tostring(indent) .. "  " .. tostring(e) .. " meta mark set " .. tostring(rule.mark) .. " counter " .. tostring(verdict) .. " comment \"" .. tostring(nft_comment("rule_id=" .. tostring(rule.rule_id))) .. "\""
      else
        lines[#lines + 1] = tostring(indent) .. "  meta mark set " .. tostring(rule.mark) .. " counter " .. tostring(verdict) .. " comment \"" .. tostring(nft_comment("rule_id=" .. tostring(rule.rule_id))) .. "\""
      end
    end
    lines[#lines + 1] = tostring(indent) .. "  return"
  end
  lines[#lines + 1] = tostring(indent) .. "}"
  if rule.requires_auth then
    local auth_chain = tostring(rule.chain) .. "_auth"
    local auth_mark = "0x00010000"
    lines[#lines + 1] = tostring(indent) .. "chain " .. tostring(auth_chain) .. " {"
    lines[#lines + 1] = tostring(indent) .. "  ether saddr @" .. tostring(rule.set_auth_mac) .. " meta mark set " .. tostring(auth_mark) .. " return comment \"auth MAC matched\""
    lines[#lines + 1] = tostring(indent) .. "  ip saddr @" .. tostring(rule.set_auth_ip4) .. " meta mark set " .. tostring(auth_mark) .. " return comment \"auth IPv4 matched\""
    lines[#lines + 1] = tostring(indent) .. "  ip6 saddr @" .. tostring(rule.set_auth_ip6) .. " meta mark set " .. tostring(auth_mark) .. " return comment \"auth IPv6 matched\""
    lines[#lines + 1] = tostring(indent) .. "  return comment \"no auth match\""
    lines[#lines + 1] = tostring(indent) .. "}"
  end
  return lines
end
local render_sets_only
render_sets_only = function(plan, indent, include_elements)
  if indent == nil then
    indent = "  "
  end
  if include_elements == nil then
    include_elements = true
  end
  local lines = { }
  lines[#lines + 1] = tostring(indent) .. "# ── b2: compiled per-rule nft sets (must be defined before chains) ──"
  lines[#lines + 1] = tostring(indent) .. "map " .. tostring(plan.action_vmap) .. " {"
  lines[#lines + 1] = tostring(indent) .. "  type mark : verdict"
  if plan and plan.action_map and #plan.action_map > 0 then
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
  else
    lines[#lines + 1] = tostring(indent) .. "  elements = { }"
  end
  lines[#lines + 1] = tostring(indent) .. "}"
  if plan and plan.all_rules then
    for _, rule in ipairs(plan.all_rules) do
      if rule.set_dyn_ip4 then
        for _, l in ipairs(render_set(rule.set_dyn_ip4, "ipv4_addr . ipv4_addr", "timeout", { }, indent, false)) do
          lines[#lines + 1] = l
        end
      end
      if rule.set_dyn_ip6 then
        for _, l in ipairs(render_set(rule.set_dyn_ip6, "ipv6_addr . ipv6_addr", "timeout", { }, indent, false)) do
          lines[#lines + 1] = l
        end
      end
      if rule.set_dyn_mac4 then
        for _, l in ipairs(render_set(rule.set_dyn_mac4, "ether_addr . ipv4_addr", "timeout", { }, indent, false)) do
          lines[#lines + 1] = l
        end
      end
      if rule.set_dyn_mac6 then
        for _, l in ipairs(render_set(rule.set_dyn_mac6, "ether_addr . ipv6_addr", "timeout", { }, indent, false)) do
          lines[#lines + 1] = l
        end
      end
    end
  end
  if plan and plan.rules then
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
      if rule.set_dst4 then
        for _, l in ipairs(render_set(rule.set_dst4, "ipv4_addr", "interval", rule.dest_ipv4, indent, include_elements)) do
          lines[#lines + 1] = l
        end
      end
      if rule.set_dst6 then
        for _, l in ipairs(render_set(rule.set_dst6, "ipv6_addr", "interval", rule.dest_ipv6, indent, include_elements)) do
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
      if rule.set_auth_mac then
        for _, l in ipairs(render_set(rule.set_auth_mac, "ether_addr", "timeout", { }, indent, false)) do
          lines[#lines + 1] = l
        end
      end
    end
  end
  return table.concat(lines, "\n")
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
    return tostring(indent) .. "chain cv_rules_dispatch {\n    return\n  }\n"
  end
  local lines = { }
  lines[#lines + 1] = tostring(indent) .. "# ── b2: compiled per-rule nft chains (staging for c1/c2) ──"
  lines[#lines + 1] = tostring(indent) .. "# first_match_wins=" .. tostring(plan.first_match_wins and 'true' or 'false')
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
    if rule.set_dst4 then
      for _, l in ipairs(render_set(rule.set_dst4, "ipv4_addr", "interval", rule.dest_ipv4, indent, include_elements)) do
        lines[#lines + 1] = l
      end
    end
    if rule.set_dst6 then
      for _, l in ipairs(render_set(rule.set_dst6, "ipv6_addr", "interval", rule.dest_ipv6, indent, include_elements)) do
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
    if rule.set_auth_mac then
      for _, l in ipairs(render_set(rule.set_auth_mac, "ether_addr", "timeout", { }, indent, false)) do
        lines[#lines + 1] = l
      end
    end
    if rule.set_auth_ip4 then
      for _, l in ipairs(render_set(rule.set_auth_ip4, "ipv4_addr", "timeout", { }, indent, false)) do
        lines[#lines + 1] = l
      end
    end
    if rule.set_auth_ip6 then
      for _, l in ipairs(render_set(rule.set_auth_ip6, "ipv6_addr", "timeout", { }, indent, false)) do
        lines[#lines + 1] = l
      end
    end
    for _, l in ipairs(render_rule_chain(rule, indent)) do
      lines[#lines + 1] = l
    end
  end
  lines[#lines + 1] = tostring(indent) .. "chain " .. tostring(plan.dispatch_chain) .. " {"
  lines[#lines + 1] = tostring(indent) .. "  comment \"b2 dispatch skeleton (not hooked before c1/c2)\""
  lines[#lines + 1] = tostring(indent) .. "  meta mark set 0x0 comment \"reset VLAN mark before dispatch\""
  for _, rule in ipairs(plan.rules) do
    lines[#lines + 1] = tostring(indent) .. "  jump " .. tostring(rule.chain) .. " comment \"" .. tostring(nft_comment("idx=" .. tostring(rule.index) .. " rule_id=" .. tostring(rule.rule_id))) .. "\""
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
  render_sets_only = render_sets_only,
  serialize_stable = serialize_stable,
  collect_subnets = collect_subnets,
  build_rule = build_rule,
  compile_conditions_nft = compile_conditions_nft,
  compile_action_nft = compile_action_nft
}
