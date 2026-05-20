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

  -- Pas d'introspection ici : les sets statiques sont remplis via les
  -- métadonnées enrichies des conditions (cf. collect_static_meta).
  table.sort v4
  table.sort v6
  v4, v6

collect_dest_nets = (cfg, rule) ->
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

  -- Pas d'introspection ici : les sets statiques sont remplis via les
  -- métadonnées enrichies des conditions (cf. collect_static_meta).
  table.sort v4
  table.sort v6
  v4, v6

--- Collect all netlist names referenced by rules.
-- @tparam table cfg Filter configuration (can be full config or cfg.filter)
-- @tparam table plan Compiled plan with rules
-- @treturn table Set of netlist names
collect_referenced_netlists = (cfg, plan) ->
  netlists = {}
  seen = {}

  add_netlist = (list_name) ->
    return unless list_name
    key = tostring(list_name)
    return if seen[key]
    -- Only include if the netlist actually exists in config
    -- Support multiple config structures (merge all locations):
    -- - Full config: cfg.nets or cfg.filter.netlists
    -- - Filter config: cfg.netlists
    -- Check all locations (not short-circuiting with or)
    found = false
    if cfg.nets and cfg.nets[list_name]
      found = true
    if cfg.netlists and cfg.netlists[list_name]
      found = true
    if cfg.filter and cfg.filter.netlists and cfg.filter.netlists[list_name]
      found = true
    if found
      seen[key] = true
      netlists[#netlists + 1] = list_name

  -- Look at original rules configuration
  rules_cfg = cfg.rules or {}
  for _, rule in ipairs rules_cfg
    for k, args in pairs rule.conditions or {}
      if k == "from_net_list" or k == "from_netlist"
        add_netlist args
      elseif k == "from_net_lists" or k == "from_netlists"
        for _, list_name in ipairs as_list args
          add_netlist list_name
      elseif k == "to_net_list" or k == "to_netlist"
        add_netlist args
      elseif k == "to_net_lists" or k == "to_netlists"
        for _, list_name in ipairs as_list args
          add_netlist list_name

  -- Also check enriched metadata if available
  if plan.rules_metadata
    for _, meta in ipairs plan.rules_metadata
      if meta.conditions
        for _, cond in ipairs meta.conditions
          -- Check if this is a from_netlist, from_netlists, to_netlist, or to_netlists condition
          if cond.name == "from_netlist" or cond.name == "to_netlist"
            -- Extract list_name from args
            list_name = nil
            if cond.args
              if type(cond.args) == "string"
                list_name = cond.args
              elseif type(cond.args) == "table"
                list_name = cond.args[1] or cond.args.list_name
            add_netlist list_name if list_name
          elseif cond.name == "from_netlists" or cond.name == "to_netlists"
            -- Extract list_names from args (array of list names)
            if cond.args and type(cond.args) == "table"
              for _, list_name in ipairs as_list cond.args
                add_netlist list_name if list_name

  table.sort netlists
  netlists

--- Render global netlist sets (nets_<name>).
-- These sets are referenced by from_netlist/to_netlist conditions.
-- @tparam table cfg Filter configuration (can be full config or cfg.filter)
-- @tparam table plan Compiled plan with rules
-- @tparam string indent Indentation string
-- @treturn string Nft set definitions for netlists
render_netlist_sets = (cfg, plan, indent="  ") ->
  netlist_names = collect_referenced_netlists cfg, plan
  return "" if #netlist_names == 0

  lines = {}
  lines[#lines + 1] = "#{indent}# ── b2: global netlist sets (nets_<name>) ──"

  -- Support multiple config structures (merge all locations):
  -- - Full config: cfg.nets or cfg.filter.netlists
  -- - Filter config: cfg.netlists
  nets_config = {}
  if cfg.nets
    for k, v in pairs cfg.nets
      nets_config[k] = v
  if cfg.netlists
    for k, v in pairs cfg.netlists
      nets_config[k] = v
  if cfg.filter and cfg.filter.netlists
    for k, v in pairs cfg.filter.netlists
      nets_config[k] = v

  for _, list_name in ipairs netlist_names
    nets = nets_config[list_name] or {}
    v4, v6 = {}, {}
    seen4, seen6 = {}, {}

    for _, raw in ipairs as_list nets
      net = tostring(raw)\match "^%s*(.-)%s*$"
      continue unless net and #net > 0
      if net\find ":", 1, true
        append_unique v6, seen6, net
      else
        append_unique v4, seen4, net

    table.sort v4
    table.sort v6

    set_name = "nets_#{list_name}"

    if #v4 > 0
      lines[#lines + 1] = "#{indent}set #{set_name} {"
      lines[#lines + 1] = "#{indent}  type ipv4_addr"
      lines[#lines + 1] = "#{indent}  flags interval"
      lines[#lines + 1] = "#{indent}  elements = { #{table.concat(v4, ", ")} }"
      lines[#lines + 1] = "#{indent}}"

    if #v6 > 0
      lines[#lines + 1] = "#{indent}set #{set_name}6 {"
      lines[#lines + 1] = "#{indent}  type ipv6_addr"
      lines[#lines + 1] = "#{indent}  flags interval"
      lines[#lines + 1] = "#{indent}  elements = { #{table.concat(v6, ", ")} }"
      lines[#lines + 1] = "#{indent}}"

  table.concat lines, "\n"

-- Agrège les métadonnées statiques publiées par les conditions enrichies.
-- Chaque condition expose éventuellement une table `nft_static` avec des
-- listes par catégorie (src_ip4, src_ip6, dst_ip4, dst_ip6, subnet_ip4,
-- subnet_ip6, times, netlist_refs). nft_compiler agrège sans connaître les
-- noms de conditions : c'est aux modules de conditions de déclarer ce
-- qu'ils contribuent.
collect_static_meta = (conditions_meta) ->
  out = {
    src_ip4: {}, src_ip6: {}
    dst_ip4: {}, dst_ip6: {}
    subnet_ip4: {}, subnet_ip6: {}
    times: {}
    netlist_refs: {}
    dns_scope: false
  }
  seen = {}
  add = (key, val) ->
    return unless val
    seen[key] or= {}
    return if seen[key][val]
    seen[key][val] = true
    out[key][#out[key] + 1] = val

  for cond in *(conditions_meta or {})
    caps = cond.capabilities
    if caps and caps.creates_dynamic_scope
      out.dns_scope = true
    if cond.creates_dynamic_scope
      out.dns_scope = true
    m = cond.nft_static
    continue unless m
    for _, v in ipairs(m.src_ip4    or {}) do add "src_ip4",     v
    for _, v in ipairs(m.src_ip6    or {}) do add "src_ip6",     v
    for _, v in ipairs(m.dst_ip4    or {}) do add "dst_ip4",     v
    for _, v in ipairs(m.dst_ip6    or {}) do add "dst_ip6",     v
    for _, v in ipairs(m.subnet_ip4 or {}) do add "subnet_ip4",  v
    for _, v in ipairs(m.subnet_ip6 or {}) do add "subnet_ip6",  v
    for _, v in ipairs(m.times      or {}) do add "times",       v
    for _, v in ipairs(m.netlist_refs or {}) do add "netlist_refs", v

  for k, v in pairs out
    if type(v) == "table"
      table.sort v
  out

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

build_rule = (cfg, rule, idx, used_ids, metadata_rule_id=nil, rule_metadata=nil) ->
  -- Use metadata rule_id if provided (must match runtime filter decision)
  rid = metadata_rule_id or stable_rule_id rule, idx, used_ids
  src4, src6 = collect_nets cfg, rule
  dst4, dst6 = collect_dest_nets cfg, rule
  -- Extraire les métadonnées statiques depuis les conditions enrichies si disponibles
  static_meta = collect_static_meta rule_metadata and rule_metadata.conditions or {}
  subnet4, subnet6 = static_meta.subnet_ip4, static_meta.subnet_ip6
  times = static_meta.times
  dns_refs = static_meta.netlist_refs
  protos, ports = collect_proto_ports rule
  action = resolve_action rule
  chain = "cv_" .. rid
  mark = string.format "0x%x", 0x4000 + idx

  requires_auth = false
  if rule_metadata and rule_metadata.conditions
    for _, cond_meta in ipairs rule_metadata.conditions
      if cond_meta.capabilities and cond_meta.capabilities.requires_auth
        requires_auth = true
        break

  {
    index: idx
    rule_id: rid
    description: rule.description or rid
    action: action or "allow"
    dns_scope: static_meta.dns_scope or #dns_refs > 0 or requires_auth
    dns_refs: dns_refs
    time_ranges: times
    source_ipv4: src4
    source_ipv6: src6
    dest_ipv4: dst4
    dest_ipv6: dst6
    subnet_ipv4: subnet4
    subnet_ipv6: subnet6
    protocols: protos
    ports: ports
    chain: chain
    mark: mark
    requires_auth: requires_auth
    set_src4: #src4 > 0 and "#{chain}_src4" or nil
    set_src6: #src6 > 0 and "#{chain}_src6" or nil
    set_dst4: #dst4 > 0 and "#{chain}_dst4" or nil
    set_dst6: #dst6 > 0 and "#{chain}_dst6" or nil
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
    rmeta = rules_metadata and rules_metadata[idx]
    meta_rid = rmeta and rmeta.rule_id
    build_rule cfg, rule, idx, used_ids, meta_rid, rmeta
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

  -- Build plan_rules in original order.
  -- A rule is included if it has at least one nft-compilable condition AND is not
  -- worker-only (fully static), OR if it requires authentication (needs auth subchains).
  -- Rules with no nft conditions (e.g. catch-all deny) are excluded to avoid
  -- bypassing QUEUE_CAPTIVE / QUEUE_REJECT in the nft template.
  plan_rules = {}

  -- Keep all rules for dynamic set generation (sets_dyn_* are needed for all rules)
  all_rules = {}

  for idx, r in ipairs rules
    verdict = if r.action == "deny" then "drop" else "accept"
    action_map[#action_map + 1] = { mark: r.mark, verdict: verdict, rule_id: r.rule_id, action: r.action }
    rules_by_id[r.rule_id] = r
    all_rules[#all_rules + 1] = r
    -- Attach enriched metadata if available
    if rules_metadata and rules_metadata[idx]
      r.conditions_meta = rules_metadata[idx].conditions
      r.actions_meta = rules_metadata[idx].actions
      r.worker_only = rules_metadata[idx].worker_only

    -- Track metrics
    is_worker_only = r.worker_only or (rules_metadata and rules_metadata[idx] and rules_metadata[idx].worker_only)
    if is_worker_only
      metrics.worker_only += 1
    else
      metrics.nft_compilable += 1

    conditions_meta = r.conditions_meta or (rules_metadata and rules_metadata[idx] and rules_metadata[idx].conditions)

    -- Count conditions by backend
    if rules_metadata and rules_metadata[idx] and rules_metadata[idx].conditions
      -- conditions is a flat array of conditions (from rule.moon)
      for _, cond in ipairs rules_metadata[idx].conditions
        if cond.capabilities and cond.capabilities.nft
          metrics.conditions_compiled += 1
        else
          metrics.conditions_worker_only += 1

    -- Determine if rule has at least one nft-compilable condition
    has_nft_cond = false
    if conditions_meta
      -- conditions_meta is a flat array of conditions (from rule.moon)
      first_elem = conditions_meta[1]
      is_flat_format = first_elem and first_elem.name and first_elem.args

      if is_flat_format
        -- conditions_meta is an array of conditions
        for _, cond_meta in ipairs conditions_meta
          if cond_meta.capabilities and cond_meta.capabilities.nft
            has_nft_cond = true
            break

    -- Include rule if:
    -- 1. Has nft conditions and is not worker-only (standard nft-compilable rule)
    -- 2. Requires auth (for auth subchain generation)
    -- 3. Has dynamic sets (need nft rules to check dynamic sets, regardless of worker_only)
    -- 4. Worker-only with dynamic sets or auth (need chains to check sets)
    include_rule = (has_nft_cond and not is_worker_only) or r.requires_auth or (r.set_dyn_ip4 or r.set_dyn_ip6 or r.set_dyn_mac4 or r.set_dyn_mac6) or (is_worker_only and (r.set_dyn_ip4 or r.set_dyn_ip6 or r.set_dyn_mac4 or r.set_dyn_mac6 or r.requires_auth))
    if include_rule
      plan_rules[#plan_rules + 1] = r

  {
    first_match_wins: first_match_wins
    dispatch_chain: "cv_rules_dispatch"
    action_vmap: "cv_action_vmap"
    rules: plan_rules
    all_rules: all_rules
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
-- Pour chaque condition qui supporte nft, appelle compile_nft avec les familles appropriées.
-- @tparam table conditions_meta Métadonnées des conditions depuis rule.compile_rule
-- @tparam string family Famille nft ("ip", "ip6", "inet")
-- @treturn table Liste des expressions nft compilées
-- @treturn boolean ok false si une condition nft-capable n'a pu être exprimée
--                    dans cette famille (sémantique AND : un seul échec l'invalide).
compile_conditions_nft = (conditions_meta, family) ->
  return {}, true unless conditions_meta and #conditions_meta > 0

  exprs = {}
  ok = true
  for _, cond_meta in ipairs conditions_meta
    -- Skip conditions that are worker-only or don't support nft
    continue unless cond_meta.capabilities
    continue unless cond_meta.capabilities.nft

    -- Call compile_nft on the condition with appropriate family
    if cond_meta.compile_nft
      expr, err = cond_meta.compile_nft family
      if expr
        exprs[#exprs + 1] = expr
      else
        if family == "inet"
          expr_ip, err_ip = cond_meta.compile_nft "ip"
          if expr_ip
            exprs[#exprs + 1] = expr_ip
          expr_ip6, err_ip6 = cond_meta.compile_nft "ip6"
          if expr_ip6
            exprs[#exprs + 1] = expr_ip6
          ok = false unless expr_ip or expr_ip6
        else
          ok = false

  exprs, ok

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
    -- conditions_meta is a flat array of conditions (from rule.moon)
    first_elem = rule.conditions_meta[1]
    is_flat_format = first_elem and first_elem.name and first_elem.args

    group_exprs = {}
    if is_flat_format
      -- Compile ip et ip6 séparément : une liste mixte IPv4/IPv6 produit deux règles.
      exprs_ip, ok_ip = compile_conditions_nft rule.conditions_meta, "ip"
      exprs_ip6, ok_ip6 = compile_conditions_nft rule.conditions_meta, "ip6"
      combined_ip = ok_ip and #exprs_ip > 0 and table.concat(exprs_ip, " ") or nil
      combined_ip6 = ok_ip6 and #exprs_ip6 > 0 and table.concat(exprs_ip6, " ") or nil

      if combined_ip and combined_ip6 and combined_ip != combined_ip6
        group_exprs[#group_exprs + 1] = combined_ip
        group_exprs[#group_exprs + 1] = combined_ip6
      elseif combined_ip
        group_exprs[#group_exprs + 1] = combined_ip
      elseif combined_ip6
        group_exprs[#group_exprs + 1] = combined_ip6

    if #group_exprs > 0
      -- OR between groups: create separate expressions for each group
      exprs = {}
      for group_expr in *group_exprs
        full_expr = table.concat({ group_expr, base }, " ")\gsub "%s+", " "
        exprs[#exprs + 1] = full_expr
      return exprs

  -- Fallback to legacy set-based matching
  exprs = {}

  -- IPv4: combine from_net/from_netlist/from_subnet with to_net/to_netlist
  if rule.set_src4 or rule.set_subnet4 or rule.set_dst4
    parts = {}
    if rule.set_src4 or rule.set_subnet4
      src_parts = { "ip saddr" }
      if rule.set_src4 and rule.set_subnet4
        src_parts[#src_parts + 1] = "{ @#{rule.set_src4}, @#{rule.set_subnet4} }"
      elseif rule.set_src4
        src_parts[#src_parts + 1] = "@#{rule.set_src4}"
      else
        src_parts[#src_parts + 1] = "@#{rule.set_subnet4}"
      parts[#parts + 1] = table.concat(src_parts, " ")
    if rule.set_dst4
      parts[#parts + 1] = "ip daddr @#{rule.set_dst4}"
    if #parts > 0
      ipv4_match = table.concat(parts, " ")
      exprs[#exprs + 1] = table.concat({ ipv4_match, base }, " ")\gsub "%s+", " "

  -- IPv6: combine from_net/from_netlist/from_subnet with to_net/to_netlist
  if rule.set_src6 or rule.set_subnet6 or rule.set_dst6
    parts = {}
    if rule.set_src6 or rule.set_subnet6
      src_parts = { "ip6 saddr" }
      if rule.set_src6 and rule.set_subnet6
        src_parts[#src_parts + 1] = "{ @#{rule.set_src6}, @#{rule.set_subnet6} }"
      elseif rule.set_src6
        src_parts[#src_parts + 1] = "@#{rule.set_src6}"
      else
        src_parts[#src_parts + 1] = "@#{rule.set_subnet6}"
      parts[#parts + 1] = table.concat(src_parts, " ")
    if rule.set_dst6
      parts[#parts + 1] = "ip6 daddr @#{rule.set_dst6}"
    if #parts > 0
      ipv6_match = table.concat(parts, " ")
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

dynamic_match_exprs = (rule, force=false) ->
  return {} unless (rule.dns_scope and rule.action != "dnsonly") or force
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

  -- For worker-only rules, accept traffic after auth check without compiling conditions
  if rule.worker_only and rule.requires_auth
    -- Worker-only rules with auth: check dynamic sets after auth check
    all_exprs = {}
    for _, expr in ipairs dynamic_match_exprs rule, true
      all_exprs[#all_exprs + 1] = expr

    for _, expr in ipairs all_exprs
      e = expr\match "^%s*(.-)%s*$"
      if e and #e > 0
        lines[#lines + 1] = "#{indent}  #{e} meta mark set #{rule.mark} counter #{verdict} comment \"#{nft_comment "rule_id=#{rule.rule_id} worker-only auth dynamic"}\""

    lines[#lines + 1] = "#{indent}  return"
  elseif rule.worker_only
    -- Worker-only rules with dynamic sets: generate simple rules to check dynamic sets
    all_exprs = {}
    for _, expr in ipairs dynamic_match_exprs rule, true
      all_exprs[#all_exprs + 1] = expr

    for _, expr in ipairs all_exprs
      e = expr\match "^%s*(.-)%s*$"
      if e and #e > 0
        lines[#lines + 1] = "#{indent}  #{e} meta mark set #{rule.mark} counter #{verdict} comment \"#{nft_comment "rule_id=#{rule.rule_id} worker-only dynamic"}\""

    lines[#lines + 1] = "#{indent}  return"
  else
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

render_sets_only = (cfg, plan, indent="  ", include_elements=true) ->
  lines = {}
  lines[#lines + 1] = "#{indent}# ── b2: compiled per-rule nft sets (must be defined before chains) ──"

  -- Render global netlist sets first
  netlist_sets = render_netlist_sets cfg, plan, indent
  if #netlist_sets > 0
    lines[#lines + 1] = netlist_sets

  lines[#lines + 1] = "#{indent}map #{plan.action_vmap} {"
  lines[#lines + 1] = "#{indent}  type mark : verdict"
  if plan and plan.action_map and #plan.action_map > 0
    entries = [ "#{e.mark} : #{e.verdict}" for e in *plan.action_map ]
    lines[#lines + 1] = "#{indent}  elements = { #{table.concat(entries, ', ')} }"
  else
    lines[#lines + 1] = "#{indent}  elements = { }"
  lines[#lines + 1] = "#{indent}}"

  -- Generate all sets (static and dynamic)
  -- Use all_rules for dynamic sets and auth sets (needed for all rules), plan.rules for static sets
  if plan and plan.all_rules
    for _, rule in ipairs plan.all_rules
      if rule.set_dyn_ip4
        for _, l in ipairs render_set rule.set_dyn_ip4, "ipv4_addr . ipv4_addr", "timeout", {}, indent, false
          lines[#lines + 1] = l
      if rule.set_dyn_ip6
        for _, l in ipairs render_set rule.set_dyn_ip6, "ipv6_addr . ipv6_addr", "timeout", {}, indent, false
          lines[#lines + 1] = l
      if rule.set_dyn_mac4
        for _, l in ipairs render_set rule.set_dyn_mac4, "ether_addr . ipv4_addr", "timeout", {}, indent, false
          lines[#lines + 1] = l
      if rule.set_dyn_mac6
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

  if plan and plan.rules
    for _, rule in ipairs plan.rules
      if rule.set_src4
        for _, l in ipairs render_set rule.set_src4, "ipv4_addr", "interval", rule.source_ipv4, indent, include_elements
          lines[#lines + 1] = l
      if rule.set_src6
        for _, l in ipairs render_set rule.set_src6, "ipv6_addr", "interval", rule.source_ipv6, indent, include_elements
          lines[#lines + 1] = l
      if rule.set_dst4
        for _, l in ipairs render_set rule.set_dst4, "ipv4_addr", "interval", rule.dest_ipv4, indent, include_elements
          lines[#lines + 1] = l
      if rule.set_dst6
        for _, l in ipairs render_set rule.set_dst6, "ipv6_addr", "interval", rule.dest_ipv6, indent, include_elements
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

  table.concat lines, "\n"

render = (plan, indent="  ", include_elements=true) ->
  return "#{indent}chain cv_rules_dispatch {\n    return\n  }\n" unless plan and plan.rules and #plan.rules > 0

  lines = {}
  lines[#lines + 1] = "#{indent}# ── b2: compiled per-rule nft chains (staging for c1/c2) ──"
  lines[#lines + 1] = "#{indent}# first_match_wins=#{plan.first_match_wins and 'true' or 'false'}"

  for _, rule in ipairs plan.rules
    if rule.set_src4
      for _, l in ipairs render_set rule.set_src4, "ipv4_addr", "interval", rule.source_ipv4, indent, include_elements
        lines[#lines + 1] = l
    if rule.set_src6
      for _, l in ipairs render_set rule.set_src6, "ipv6_addr", "interval", rule.source_ipv6, indent, include_elements
        lines[#lines + 1] = l
    if rule.set_dst4
      for _, l in ipairs render_set rule.set_dst4, "ipv4_addr", "interval", rule.dest_ipv4, indent, include_elements
        lines[#lines + 1] = l
    if rule.set_dst6
      for _, l in ipairs render_set rule.set_dst6, "ipv6_addr", "interval", rule.dest_ipv6, indent, include_elements
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

{ :compile, :render, :render_sets_only, :render_netlist_sets, :collect_referenced_netlists, :serialize_stable, :build_rule, :compile_conditions_nft, :compile_action_nft }
