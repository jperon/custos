-- src/filter/nft_compiler.moon
-- Compilation des règles filter.* en objets nft "préparatoires".
--
-- Cette phase (b2) produit une architecture par règle (sets/maps/chains) avec
-- rule_id stable, sans brancher la sémantique finale DNS/IPC (c1/c2).

bit = require "bit"

is_array = (t) ->
  return false unless type(t) == "table"
  n = #t
  return false if n == 0
  for i = 1, n
    return false if t[i] == nil
  true

as_list = (v) ->
  return {} if v == nil
  return v if type(v) == "table" and is_array(v)
  { v }

sorted_keys = (t) ->
  keys = [k for k in pairs t]
  table.sort keys, (a, b) -> tostring(a) < tostring(b)
  keys

serialize_stable = (v) ->
  tv = type v
  return "null" if tv == "nil"
  return tostring(v) if tv == "boolean" or tv == "number"
  return string.format "%q", v if tv == "string"
  return string.format "%q", tostring(v) unless tv == "table"

  if is_array v
    parts = [serialize_stable item for item in *v]
    return "[" .. table.concat(parts, ",") .. "]"

  keys = sorted_keys v
  parts = {}
  for _, k in ipairs keys
    parts[#parts + 1] = "#{serialize_stable k}:#{serialize_stable v[k]}"
  "{" .. table.concat(parts, ",") .. "}"

fnv1a32_hex = (s) ->
  hash = 2166136261
  for i = 1, #s
    hash = bit.bxor hash, s\byte i
    hash = (hash * 16777619) % 4294967296
  string.format "%08x", hash

sanitize_id = (raw) ->
  s = tostring(raw or "")\lower!
  s = s\gsub "[^a-z0-9_%-]+", "_"
  s = s\gsub "_+", "_"
  s = s\gsub "^_+", ""
  s = s\gsub "_+$", ""
  s = s\gsub "%-+", "_"
  if #s == 0
    s = "rule"
  if #s > 40
    s = s\sub 1, 40
  s

stable_rule_id = (rule, idx, used) ->
  explicit = rule.rule_id
  base = nil

  if explicit and tostring(explicit)\match "%S"
    base = sanitize_id explicit
  else
    canonical = serialize_stable {
      description: rule.description or ""
      conditions: rule.conditions or {}
      actions: rule.actions or {}
      network: rule.network or {}
    }
    base = "r_" .. fnv1a32_hex canonical

  rid = base
  n = 1
  while used[rid]
    n += 1
    rid = "#{base}_#{n}"
  used[rid] = true
  rid

append_unique = (dst, seen, val) ->
  return unless val and tostring(val)\match "%S"
  key = tostring val
  return if seen[key]
  seen[key] = true
  dst[#dst + 1] = key

collect_nets = (cfg, rule) ->
  v4, v6 = {}, {}
  seen4, seen6 = {}, {}
  named = cfg.nets or {}

  add_net = (raw) ->
    return unless raw
    net = tostring(raw)\match "^%s*(.-)%s*$"
    return unless net and #net > 0
    if net\find ":", 1, true
      append_unique v6, seen6, net
    else
      append_unique v4, seen4, net

  add_named = (list_name) ->
    return unless list_name
    nets = named[list_name] or {}
    for _, n in ipairs as_list nets
      add_net n

  for _, cond in ipairs rule.conditions or {}
    continue unless type(cond) == "table"
    for k, args in pairs cond
      if k == "from_net"
        add_net args
      elseif k == "from_nets"
        for _, n in ipairs as_list args
          add_net n
      elseif k == "from_netlist"
        add_named args
      elseif k == "from_netlists"
        for _, list_name in ipairs as_list args
          add_named list_name

  table.sort v4
  table.sort v6
  v4, v6

collect_times = (rule) ->
  out = {}
  seen = {}
  for _, cond in ipairs rule.conditions or {}
    continue unless type(cond) == "table"
    for k, args in pairs cond
      if k == "in_time"
        append_unique out, seen, args
      elseif k == "in_times"
        for _, t in ipairs as_list args
          append_unique out, seen, t
  table.sort out
  out

collect_dns = (rule) ->
  refs = {}
  seen = {}
  dns_keys = {
    to_domain: true
    to_domains: true
    to_domainlist: true
    to_domainlists: true
  }
  for _, cond in ipairs rule.conditions or {}
    continue unless type(cond) == "table"
    for k, args in pairs cond
      if dns_keys[k]
        if k == "to_domain" or k == "to_domainlist"
          append_unique refs, seen, "#{k}:#{tostring(args)}"
        else
          for _, v in ipairs as_list args
            append_unique refs, seen, "#{k}:#{tostring(v)}"
  table.sort refs
  refs

normalize_proto = (p) ->
  v = tostring(p)\lower!
  if v == "tcp" or v == "udp" or v == "icmp" or v == "icmpv6"
    return v
  nil

collect_proto_ports = (rule) ->
  net = rule.network or {}
  protos = {}
  seen_proto = {}
  ports = {}
  seen_port = {}

  proto_src = net.proto or net.protocol or net.protocols
  for _, p in ipairs as_list proto_src
    n = normalize_proto p
    append_unique protos, seen_proto, n if n

  port_src = net.ports or net.dports or net.dest_ports
  for _, p in ipairs as_list port_src
    raw = tostring(p)\match "^%s*(.-)%s*$"
    continue unless raw and #raw > 0
    if raw\match "^%d+$"
      append_unique ports, seen_port, raw
    else
      from_s, to_s = raw\match "^(%d+)%-(%d+)$"
      if from_s and to_s
        append_unique ports, seen_port, "#{tonumber(from_s)}-#{tonumber(to_s)}"

  table.sort protos
  table.sort ports
  protos, ports

resolve_action = (rule) ->
  for _, action in ipairs rule.actions or {}
    if action == "allow" or action == "deny" or action == "dnsonly"
      return action
  nil

build_rule = (cfg, rule, idx, used_ids) ->
  rid = stable_rule_id rule, idx, used_ids
  src4, src6 = collect_nets cfg, rule
  times = collect_times rule
  dns_refs = collect_dns rule
  protos, ports = collect_proto_ports rule
  action = resolve_action rule
  chain = "cv_rule_" .. rid
  mark = string.format "0x%x", 0x4000 + idx

  {
    index: idx
    rule_id: rid
    description: rule.description or rid
    action: action or "allow"
    dns_scope: #dns_refs > 0
    dns_refs: dns_refs
    time_ranges: times
    source_ipv4: src4
    source_ipv6: src6
    protocols: protos
    ports: ports
    chain: chain
    mark: mark
    set_src4: #src4 > 0 and "#{chain}_src4" or nil
    set_src6: #src6 > 0 and "#{chain}_src6" or nil
    set_ports: #ports > 0 and "#{chain}_dports" or nil
    stubs: {
      time_match: #times > 0
      dns_match: #dns_refs > 0
    }
  }

compile = (filter_cfg) ->
  cfg = filter_cfg or {}
  rules_cfg = cfg.rules or {}
  decision = cfg.decision or {}
  first_match_wins = if decision.first_match_wins == nil then true else not not decision.first_match_wins

  used_ids = {}
  rules = [build_rule(cfg, rule, idx, used_ids) for idx, rule in ipairs rules_cfg]
  action_map = {}
  rules_by_id = {}
  for _, r in ipairs rules
    verdict = if r.action == "deny" then "drop" else "accept"
    action_map[#action_map + 1] = { mark: r.mark, verdict: verdict, rule_id: r.rule_id, action: r.action }
    rules_by_id[r.rule_id] = r

  {
    first_match_wins: first_match_wins
    dispatch_chain: "cv_rules_dispatch"
    action_vmap: "cv_rule_action_vmap"
    rules: rules
    rules_by_id: rules_by_id
    action_map: action_map
  }

render_set = (name, set_type, flags, elems, indent) ->
  lines = {}
  lines[#lines + 1] = "#{indent}set #{name} {"
  lines[#lines + 1] = "#{indent}  type #{set_type}"
  lines[#lines + 1] = "#{indent}  flags #{flags}" if flags and #flags > 0
  lines[#lines + 1] = "#{indent}  elements = { #{table.concat elems, ", "} }" if elems and #elems > 0
  lines[#lines + 1] = "#{indent}}"
  lines

match_exprs = (rule) ->
  l4 = {}
  if #rule.protocols > 0
    l4[#l4 + 1] = "meta l4proto { #{table.concat(rule.protocols, ", ")} }"
  if rule.set_ports
    l4[#l4 + 1] = "th dport @#{rule.set_ports}"
  base = table.concat l4, " "

  exprs = {}
  if rule.set_src4
    exprs[#exprs + 1] = table.concat({ "ip saddr @#{rule.set_src4}", base }, " ")\gsub "%s+", " "
  if rule.set_src6
    exprs[#exprs + 1] = table.concat({ "ip6 saddr @#{rule.set_src6}", base }, " ")\gsub "%s+", " "
  if #exprs == 0
    exprs[1] = base
  exprs

render_rule_chain = (rule, indent) ->
  lines = {}
  lines[#lines + 1] = "#{indent}chain #{rule.chain} {"
  lines[#lines + 1] = "#{indent}  comment \"custos rule_id=#{rule.rule_id} action=#{rule.action}\""
  lines[#lines + 1] = "#{indent}  counter comment \"dns_scope=#{rule.dns_scope and 'yes' or 'no'}\""
  if rule.stubs.time_match
    lines[#lines + 1] = "#{indent}  counter comment \"stub:time_ranges=#{table.concat(rule.time_ranges, ',')}\""

  for _, expr in ipairs match_exprs rule
    e = expr\match "^%s*(.-)%s*$"
    if e and #e > 0
      lines[#lines + 1] = "#{indent}  #{e} meta mark set #{rule.mark} counter return comment \"rule_id=#{rule.rule_id}\""
    else
      lines[#lines + 1] = "#{indent}  meta mark set #{rule.mark} counter return comment \"rule_id=#{rule.rule_id}\""

  lines[#lines + 1] = "#{indent}  return"
  lines[#lines + 1] = "#{indent}}"
  lines

render = (plan, indent="  ") ->
  return "#{indent}# b2: no compiled rule objects\n" unless plan and plan.rules and #plan.rules > 0

  lines = {}
  lines[#lines + 1] = "#{indent}# ── b2: compiled per-rule nft objects (staging for c1/c2) ──"
  lines[#lines + 1] = "#{indent}# first_match_wins=#{plan.first_match_wins and 'true' or 'false'}"

  lines[#lines + 1] = "#{indent}map #{plan.action_vmap} {"
  lines[#lines + 1] = "#{indent}  type mark : verdict"
  entries = [ "#{e.mark} : #{e.verdict}" for e in *plan.action_map ]
  lines[#lines + 1] = "#{indent}  elements = { #{table.concat(entries, ', ')} }"
  lines[#lines + 1] = "#{indent}}"

  for _, rule in ipairs plan.rules
    if rule.set_src4
      for _, l in ipairs render_set rule.set_src4, "ipv4_addr", "interval", rule.source_ipv4, indent
        lines[#lines + 1] = l
    if rule.set_src6
      for _, l in ipairs render_set rule.set_src6, "ipv6_addr", "interval", rule.source_ipv6, indent
        lines[#lines + 1] = l
    if rule.set_ports
      for _, l in ipairs render_set rule.set_ports, "inet_service", "", rule.ports, indent
        lines[#lines + 1] = l
    for _, l in ipairs render_rule_chain rule, indent
      lines[#lines + 1] = l

  lines[#lines + 1] = "#{indent}chain #{plan.dispatch_chain} {"
  lines[#lines + 1] = "#{indent}  comment \"b2 dispatch skeleton (not hooked before c1/c2)\""
  for _, rule in ipairs plan.rules
    lines[#lines + 1] = "#{indent}  jump #{rule.chain} comment \"idx=#{rule.index} rule_id=#{rule.rule_id}\""
    if plan.first_match_wins
      lines[#lines + 1] = "#{indent}  meta mark != 0x0 return comment \"first_match_wins\""
  lines[#lines + 1] = "#{indent}  return"
  lines[#lines + 1] = "#{indent}}"
  table.concat(lines, "\n") .. "\n"

{ :compile, :render, :serialize_stable }
