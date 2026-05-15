-- src/filter/nft_compiler.moon
-- Compilation des règles filter.* en objets nft "préparatoires".
--
-- Cette phase (b2) produit une architecture par règle (sets/maps/chains) avec
-- rule_id stable, sans brancher la sémantique finale DNS/IPC (c1/c2).

compiler_api = require "filter.compiler_api"
sanitize_ascii = compiler_api.sanitize_ascii
sanitize_id = compiler_api.sanitize_id
NFT_COMMENT_MAX = 128

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

rule_id = require "filter.rule_id"

stable_rule_id = rule_id.generate_unique

nft_comment = (text) ->
  s = sanitize_ascii text
  if #s > NFT_COMMENT_MAX
    s\sub 1, NFT_COMMENT_MAX
  else
    s

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

collect_subnets = (rule) ->
  v4, v6 = {}, {}
  seen4, seen6 = {}, {}

  add_subnet = (cidr_str) ->
    return unless cidr_str
    net = tostring(cidr_str)\match "^%s*(.-)%s*$"
    return unless net and #net > 0
    if net\find ":", 1, true
      append_unique v6, seen6, net
    else
      append_unique v4, seen4, net

  for _, cond in ipairs rule.conditions or {}
    continue unless type(cond) == "table"
    for k, args in pairs cond
      if k == "from_subnet"
        if type(args) == "string"
          add_subnet args
        elseif type(args) == "table" and args.net
          add_subnet args.net
      elseif k == "from_subnets"
        for _, subnet_spec in ipairs as_list args
          if type(subnet_spec) == "string"
            add_subnet subnet_spec
          elseif type(subnet_spec) == "table" and subnet_spec.net
            add_subnet subnet_spec.net

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

build_rule = (cfg, rule, idx, used_ids, metadata_rule_id=nil) ->
  -- Use metadata rule_id if provided (must match runtime filter decision)
  rid = metadata_rule_id or stable_rule_id rule, idx, used_ids
  src4, src6 = collect_nets cfg, rule
  subnet4, subnet6 = collect_subnets rule
  times = collect_times rule
  dns_refs = collect_dns rule
  protos, ports = collect_proto_ports rule
  action = resolve_action rule
  chain = "cv_rule_" .. rid
  mark = string.format "0x%x", 0x4000 + idx

  -- Check if rule requires authentication (has from_users or from_userlists)
  requires_auth = false
  for _, cond in ipairs rule.conditions or {}
    continue unless type(cond) == "table"
    for k, _ in pairs cond
      if k == "from_users" or k == "from_userlists"
        requires_auth = true
        break
    break if requires_auth

  {
    index: idx
    rule_id: rid
    description: rule.description or rid
    action: action or "allow"
    dns_scope: #dns_refs > 0  -- Only set dns_scope if there are DNS conditions
    dns_refs: dns_refs
    time_ranges: times
    source_ipv4: src4
    source_ipv6: src6
    subnet_ipv4: subnet4
    subnet_ipv6: subnet6
    protocols: protos
    ports: ports
    chain: chain
    mark: mark
    requires_auth: requires_auth
    set_src4: #src4 > 0 and "#{chain}_src4" or nil
    set_src6: #src6 > 0 and "#{chain}_src6" or nil
    set_subnet4: #subnet4 > 0 and "#{chain}_subnet4" or nil
    set_subnet6: #subnet6 > 0 and "#{chain}_subnet6" or nil
    set_ports: #ports > 0 and "#{chain}_dports" or nil
    set_dyn_ip4: "#{rid}_ip4"
    set_dyn_ip6: "#{rid}_ip6"
    set_dyn_mac4: "#{rid}_mac4"
    set_dyn_mac6: "#{rid}_mac6"
    set_auth_mac: requires_auth and "#{rid}_auth_mac" or nil
    set_auth_ip4: requires_auth and "#{rid}_auth_ip4" or nil
    set_auth_ip6: requires_auth and "#{rid}_auth_ip6" or nil
    stubs: {
      time_match: #times > 0
      dns_match: #dns_refs > 0
    }
  }

compile = (filter_cfg, rules_metadata=nil) ->
  cfg = filter_cfg or {}
  rules_cfg = cfg.rules or {}
  decision = cfg.decision or {}
  first_match_wins = if decision.first_match_wins == nil then true else not not decision.first_match_wins

  used_ids = {}
  rules = for idx, rule in ipairs rules_cfg
    -- Get rule_id from metadata if available (ensures consistency with runtime)
    meta_rid = rules_metadata and rules_metadata[idx] and rules_metadata[idx].rule_id
    build_rule cfg, rule, idx, used_ids, meta_rid
  action_map = {}
  rules_by_id = {}

  -- Compilation metrics
  metrics = {
    total_rules: #rules
    nft_compilable: 0
    worker_only: 0
    conditions_compiled: 0
    conditions_worker_only: 0
  }

  for idx, r in ipairs rules
    verdict = if r.action == "deny" then "drop" else "accept"
    action_map[#action_map + 1] = { mark: r.mark, verdict: verdict, rule_id: r.rule_id, action: r.action }
    rules_by_id[r.rule_id] = r
    -- Attach enriched metadata if available
    if rules_metadata and rules_metadata[idx]
      r.conditions_meta = rules_metadata[idx].conditions
      r.actions_meta = rules_metadata[idx].actions
      r.worker_only = rules_metadata[idx].worker_only

      -- Track metrics
      if rules_metadata[idx].worker_only
        metrics.worker_only += 1
      else
        metrics.nft_compilable += 1

      -- Count conditions by backend
      if rules_metadata[idx].conditions
        for _, cond in ipairs rules_metadata[idx].conditions
          if cond.capabilities and cond.capabilities.nft_static
            metrics.conditions_compiled += 1
          else
            metrics.conditions_worker_only += 1

  {
    first_match_wins: first_match_wins
    dispatch_chain: "cv_rules_dispatch"
    action_vmap: "cv_rule_action_vmap"
    rules: rules
    rules_by_id: rules_by_id
    action_map: action_map
    rules_metadata: rules_metadata
    metrics: metrics
  }

render_set = (name, set_type, flags, elems, indent, include_elements=true) ->
  lines = {}
  lines[#lines + 1] = "#{indent}set #{name} {"
  lines[#lines + 1] = "#{indent}  type #{set_type}"
  lines[#lines + 1] = "#{indent}  flags #{flags}" if flags and #flags > 0
  lines[#lines + 1] = "#{indent}  elements = { #{table.concat elems, ", "} }" if include_elems and elems and #elems > 0
  lines[#lines + 1] = "#{indent}}"
  lines

--- Compile les conditions enrichies en expressions nft.
-- Pour chaque condition qui supporte nft_static, appelle compile_nft(family).
-- @tparam table conditions_meta Métadonnées des conditions depuis rule.compile_rule
-- @tparam string family Famille nft ("ip", "ip6", "inet")
-- @treturn table Liste des expressions nft compilées
compile_conditions_nft = (conditions_meta, family) ->
  return {} unless conditions_meta and #conditions_meta > 0

  exprs = {}
  for _, cond_meta in ipairs conditions_meta
    -- Skip conditions that are worker-only or don't support nft_static
    continue unless cond_meta.capabilities
    continue unless cond_meta.capabilities.nft_static

    -- Call compile_nft on the condition
    if cond_meta.compile_nft
      expr, err = cond_meta.compile_nft family
      if expr
        exprs[#exprs + 1] = expr

  exprs

--- Compile l'action enrichie en verdict nft.
-- @tparam table actions_meta Métadonnées des actions depuis rule.compile_rule
-- @treturn string|nil Verdict nft ("accept", "drop", etc.) ou nil si worker-only
compile_action_nft = (actions_meta) ->
  return nil unless actions_meta and #actions_meta > 0

  for _, act_meta in ipairs actions_meta
    -- Use first action that supports nft
    if act_meta.capabilities and act_meta.capabilities.nft
      if act_meta.compile_nft
        verdict, _ = act_meta.compile_nft!
        return verdict if verdict

  nil

match_exprs = (rule) ->
  l4 = {}
  if #rule.protocols > 0
    l4[#l4 + 1] = "meta l4proto { #{table.concat(rule.protocols, ", ")} }"
  if rule.set_ports
    l4[#l4 + 1] = "th dport @#{rule.set_ports}"
  base = table.concat l4, " "

  -- If enriched metadata available, use compile_conditions_nft
  if rule.conditions_meta
    compiled_exprs = compile_conditions_nft rule.conditions_meta, "inet"
    if #compiled_exprs > 0
      exprs = {}
      for _, expr in ipairs compiled_exprs
        exprs[#exprs + 1] = table.concat({ expr, base }, " ")\gsub "%s+", " "
      return exprs

  -- Fallback to legacy set-based matching
  exprs = {}
  
  -- IPv4: from_net, from_netlist, and from_subnet
  if rule.set_src4 or rule.set_subnet4
    expr_parts = { "ip saddr" }
    if rule.set_src4 and rule.set_subnet4
      expr_parts[#expr_parts + 1] = "{ @#{rule.set_src4}, @#{rule.set_subnet4} }"
    elseif rule.set_src4
      expr_parts[#expr_parts + 1] = "@#{rule.set_src4}"
    else
      expr_parts[#expr_parts + 1] = "@#{rule.set_subnet4}"
    
    ipv4_match = table.concat(expr_parts, " ")
    exprs[#exprs + 1] = table.concat({ ipv4_match, base }, " ")\gsub "%s+", " "
  
  -- IPv6: from_net, from_netlist, and from_subnet
  if rule.set_src6 or rule.set_subnet6
    expr_parts = { "ip6 saddr" }
    if rule.set_src6 and rule.set_subnet6
      expr_parts[#expr_parts + 1] = "{ @#{rule.set_src6}, @#{rule.set_subnet6} }"
    elseif rule.set_src6
      expr_parts[#expr_parts + 1] = "@#{rule.set_src6}"
    else
      expr_parts[#expr_parts + 1] = "@#{rule.set_subnet6}"
    
    ipv6_match = table.concat(expr_parts, " ")
    exprs[#exprs + 1] = table.concat({ ipv6_match, base }, " ")\gsub "%s+", " "
  
  if rule.set_dyn_mac6
    exprs[#exprs + 1] = "ether saddr . ip6 daddr @#{rule.set_dyn_mac6} #{base}"\gsub "%s+", " "
  if rule.set_dyn_mac4
    exprs[#exprs + 1] = "ether saddr . ip daddr @#{rule.set_dyn_mac4} #{base}"\gsub "%s+", " "
  if rule.set_dyn_ip6
    exprs[#exprs + 1] = "ip6 saddr . ip6 daddr @#{rule.set_dyn_ip6} #{base}"\gsub "%s+", " "
  if rule.set_dyn_ip4
    exprs[#exprs + 1] = "ip saddr . ip daddr @#{rule.set_dyn_ip4} #{base}"\gsub "%s+", " "
  
  if #exprs == 0
    exprs[1] = base
  exprs

dynamic_match_exprs = (rule) ->
  return {} unless rule.dns_scope and rule.action != "dnsonly"
  l4 = {}
  if #rule.protocols > 0
    l4[#l4 + 1] = "meta l4proto { #{table.concat(rule.protocols, ", ")} }"
  if rule.set_ports
    l4[#l4 + 1] = "th dport @#{rule.set_ports}"
  base = table.concat l4, " "
  parts = {
    "ether saddr . ip6 daddr @#{rule.set_dyn_mac6}"
    "ether saddr . ip daddr @#{rule.set_dyn_mac4}"
    "ip6 saddr . ip6 daddr @#{rule.set_dyn_ip6}"
    "ip saddr . ip daddr @#{rule.set_dyn_ip4}"
  }
  out = {}
  for _, p in ipairs parts
    out[#out + 1] = table.concat({ p, base }, " ")\gsub "%s+", " "
  out

render_rule_chain = (rule, indent) ->
  lines = {}
  lines[#lines + 1] = "#{indent}chain #{rule.chain} {"
  lines[#lines + 1] = "#{indent}  comment \"#{nft_comment "custos rule_id=#{rule.rule_id} action=#{rule.action}"}\""
  lines[#lines + 1] = "#{indent}  counter comment \"dns_scope=#{rule.dns_scope and 'yes' or 'no'}\""
  if rule.stubs.time_match
    lines[#lines + 1] = "#{indent}  counter comment \"stub:time_ranges=#{table.concat(rule.time_ranges, ',')}\""

  verdict = if rule.action == "deny" then "drop" else "accept"

  -- Auth check: if requires_auth, jump to auth subchain and check mark
  if rule.requires_auth
    auth_chain = "#{rule.chain}_auth"
    auth_mark = "0x00010000"  -- Use bit 16 to avoid conflict with VLAN mark (bits 0-11)
    -- Reset VLAN mark (bits 0-11) and auth mark (bits 16+) to 0
    lines[#lines + 1] = "#{indent}  meta mark set 0x00000000 comment \"reset VLAN and auth marks\""
    lines[#lines + 1] = "#{indent}  jump #{auth_chain} comment \"check authentication\""
    lines[#lines + 1] = "#{indent}  meta mark != #{auth_mark} return comment \"no auth match\""

  all_exprs = {}
  for _, expr in ipairs dynamic_match_exprs rule
    all_exprs[#all_exprs + 1] = expr
  unless rule.dns_scope
    for _, expr in ipairs match_exprs rule
      all_exprs[#all_exprs + 1] = expr

  for _, expr in ipairs all_exprs
    e = expr\match "^%s*(.-)%s*$"
    if e and #e > 0
      lines[#lines + 1] = "#{indent}  #{e} meta mark set #{rule.mark} counter #{verdict} comment \"#{nft_comment "rule_id=#{rule.rule_id}"}\""
    else
      lines[#lines + 1] = "#{indent}  meta mark set #{rule.mark} counter #{verdict} comment \"#{nft_comment "rule_id=#{rule.rule_id}"}\""

  lines[#lines + 1] = "#{indent}  return"
  lines[#lines + 1] = "#{indent}}"

  -- Render auth subchain if requires_auth
  if rule.requires_auth
    auth_chain = "#{rule.chain}_auth"
    auth_mark = "0x00010000"  -- Use bit 16 to avoid conflict with VLAN mark (bits 0-11)
    lines[#lines + 1] = "#{indent}chain #{auth_chain} {"
    lines[#lines + 1] = "#{indent}  ether saddr @#{rule.set_auth_mac} meta mark set #{auth_mark} return comment \"auth MAC matched\""
    lines[#lines + 1] = "#{indent}  ip saddr @#{rule.set_auth_ip4} meta mark set #{auth_mark} return comment \"auth IPv4 matched\""
    lines[#lines + 1] = "#{indent}  ip6 saddr @#{rule.set_auth_ip6} meta mark set #{auth_mark} return comment \"auth IPv6 matched\""
    lines[#lines + 1] = "#{indent}  return comment \"no auth match\""
    lines[#lines + 1] = "#{indent}}"

  lines

render = (plan, indent="  ", include_elements=true) ->
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
      for _, l in ipairs render_set rule.set_src4, "ipv4_addr", "interval", rule.source_ipv4, indent, include_elements
        lines[#lines + 1] = l
    if rule.set_src6
      for _, l in ipairs render_set rule.set_src6, "ipv6_addr", "interval", rule.source_ipv6, indent, include_elements
        lines[#lines + 1] = l
    if rule.set_subnet4
      for _, l in ipairs render_set rule.set_subnet4, "ipv4_addr", "interval", rule.subnet_ipv4, indent, include_elements
        lines[#lines + 1] = l
    if rule.set_subnet6
      for _, l in ipairs render_set rule.set_subnet6, "ipv6_addr", "interval", rule.subnet_ipv6, indent, include_elements
        lines[#lines + 1] = l
    if rule.set_ports
      for _, l in ipairs render_set rule.set_ports, "inet_service", "", rule.ports, indent, include_elements
        lines[#lines + 1] = l
    for _, l in ipairs render_set rule.set_dyn_ip4, "ipv4_addr . ipv4_addr", "timeout", {}, indent, false
      lines[#lines + 1] = l
    for _, l in ipairs render_set rule.set_dyn_ip6, "ipv6_addr . ipv6_addr", "timeout", {}, indent, false
      lines[#lines + 1] = l
    for _, l in ipairs render_set rule.set_dyn_mac4, "ether_addr . ipv4_addr", "timeout", {}, indent, false
      lines[#lines + 1] = l
    for _, l in ipairs render_set rule.set_dyn_mac6, "ether_addr . ipv6_addr", "timeout", {}, indent, false
      lines[#lines + 1] = l
    if rule.set_auth_mac
      for _, l in ipairs render_set rule.set_auth_mac, "ether_addr", "timeout", {}, indent, false
        lines[#lines + 1] = l
    if rule.set_auth_ip4
      for _, l in ipairs render_set rule.set_auth_ip4, "ipv4_addr", "timeout", {}, indent, false
        lines[#lines + 1] = l
    if rule.set_auth_ip6
      for _, l in ipairs render_set rule.set_auth_ip6, "ipv6_addr", "timeout", {}, indent, false
        lines[#lines + 1] = l
    for _, l in ipairs render_rule_chain rule, indent
      lines[#lines + 1] = l

  lines[#lines + 1] = "#{indent}chain #{plan.dispatch_chain} {"
  lines[#lines + 1] = "#{indent}  comment \"b2 dispatch skeleton (not hooked before c1/c2)\""
  lines[#lines + 1] = "#{indent}  meta mark set 0x0 comment \"reset VLAN mark before dispatch\""
  for _, rule in ipairs plan.rules
    lines[#lines + 1] = "#{indent}  jump #{rule.chain} comment \"#{nft_comment "idx=#{rule.index} rule_id=#{rule.rule_id}"}\""
    if plan.first_match_wins
      lines[#lines + 1] = "#{indent}  meta mark != 0x0 return comment \"first_match_wins\""
  lines[#lines + 1] = "#{indent}  return"
  lines[#lines + 1] = "#{indent}}"
  table.concat(lines, "\n") .. "\n"

{ :compile, :render, :serialize_stable, :collect_subnets, :build_rule, :compile_conditions_nft, :compile_action_nft }
