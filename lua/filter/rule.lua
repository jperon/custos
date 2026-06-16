local compiler_api = require("filter.compiler_api")
local compile_rule
compile_rule = function(cfg, rule, idx, used_ids)
  if used_ids == nil then
    used_ids = nil
  end
  local conditions_eval = { }
  local conditions_meta = { }
  local condition_table = rule.conditions or { }
  if not (type(condition_table) == "table") then
    error("Conditions doit être une table, got " .. tostring(type(condition_table)))
  end
  for name, args in pairs(condition_table) do
    local cond_factory, err = compiler_api.load_condition(name)
    if not (cond_factory) then
      error("Condition inconnue '" .. tostring(name) .. "': " .. tostring(err))
    end
    local cond_obj = cond_factory(cfg)(args)
    conditions_eval[#conditions_eval + 1] = cond_obj.eval
    conditions_meta[#conditions_meta + 1] = {
      name = name,
      args = args,
      capabilities = cond_obj.capabilities,
      worker_only = compiler_api.compute_worker_only(cond_obj),
      compile_nft = cond_obj.compile_nft,
      creates_dynamic_scope = cond_obj.creates_dynamic_scope,
      negate_mark = cond_obj.negate_mark or false
    }
  end
  local action_evals = { }
  local actions_meta = { }
  local rule_block_modifiers = { }
  local rule_allow_modifiers = { }
  local _list_0 = (rule.actions or { })
  for _index_0 = 1, #_list_0 do
    local action_name = _list_0[_index_0]
    local action_factory, err = compiler_api.load_action(action_name)
    if not (action_factory) then
      error("Action inconnue '" .. tostring(action_name) .. "': " .. tostring(err))
    end
    local action_obj = action_factory(cfg)(rule)
    action_evals[#action_evals + 1] = action_obj.eval
    actions_meta[#actions_meta + 1] = {
      name = action_name,
      capabilities = action_obj.capabilities,
      worker_only = compiler_api.compute_worker_only(action_obj),
      compile_nft = action_obj.compile_nft,
      verdict = action_obj.verdict,
      on_response = action_obj.on_response,
      redirects_destination = action_obj.redirects_destination,
      cname_target = action_obj.cname_target
    }
    if action_obj.block_modifiers then
      for k, v in pairs(action_obj.block_modifiers) do
        rule_block_modifiers[k] = v
      end
    end
    if action_obj.allow_modifiers then
      for k, v in pairs(action_obj.allow_modifiers) do
        rule_allow_modifiers[k] = v
      end
    end
  end
  local rule_desc = rule.description or "rule_" .. tostring(idx)
  local rule_id = compiler_api.unique_rule_id(rule, idx, used_ids)
  local rule_timeout = rule.nft_timeout or (cfg.nft and cfg.nft.ip_timeout) or "2m"
  local on_response_list
  do
    local _accum_0 = { }
    local _len_0 = 1
    for _index_0 = 1, #actions_meta do
      local am = actions_meta[_index_0]
      if am.on_response then
        _accum_0[_len_0] = am.on_response
        _len_0 = _len_0 + 1
      end
    end
    on_response_list = _accum_0
  end
  local rule_redirects_destination = false
  local rule_cname_target = nil
  for _index_0 = 1, #actions_meta do
    local am = actions_meta[_index_0]
    if am.redirects_destination then
      rule_redirects_destination = true
      rule_cname_target = am.cname_target or rule_cname_target
    end
  end
  local metadata = {
    rule_id = rule_id,
    description = rule_desc,
    timeout = rule_timeout,
    conditions = conditions_meta,
    actions = actions_meta,
    on_response = on_response_list
  }
  metadata.worker_only = false
  if type(rule_allow_modifiers.validate) == "table" then
    metadata.validate_resolvers = rule_allow_modifiers.validate
  end
  for _index_0 = 1, #conditions_meta do
    local cond = conditions_meta[_index_0]
    if cond.worker_only then
      metadata.worker_only = true
      break
    end
  end
  if not (metadata.worker_only) then
    for _index_0 = 1, #actions_meta do
      local act = actions_meta[_index_0]
      if act.worker_only then
        metadata.worker_only = true
        break
      end
    end
  end
  metadata.redirects_destination = rule_redirects_destination
  metadata.cname_target = rule_cname_target
  metadata.creates_dynamic_scope = false
  for _index_0 = 1, #conditions_meta do
    local cond_meta = conditions_meta[_index_0]
    if cond_meta.creates_dynamic_scope then
      metadata.creates_dynamic_scope = true
      break
    end
  end
  local rule_has_on_response = #on_response_list > 0
  local eval_fn
  eval_fn = function(req)
    local all_passed = true
    local condition_reason = nil
    for _index_0 = 1, #conditions_eval do
      local cond = conditions_eval[_index_0]
      local ok, cond_msg = cond(req)
      if not (ok) then
        all_passed = false
        break
      end
      if condition_reason == nil and cond_msg then
        condition_reason = cond_msg
      end
    end
    if not (all_passed) then
      return nil, "No condition matched", nil, nil, nil, nil, nil, nil, false, false, false, nil
    end
    req._condition_reason = condition_reason
    local verdict, msg
    for _index_0 = 1, #action_evals do
      local action_eval = action_evals[_index_0]
      local v, m = action_eval(req)
      if v ~= nil and verdict == nil then
        verdict = v
        msg = m or msg
      elseif v == nil and m then
        msg = msg or m
      end
    end
    return verdict, msg, rule_id, rule_timeout, rule_desc, rule_block_modifiers, condition_reason, rule_allow_modifiers, true, rule_has_on_response, rule_redirects_destination, rule_cname_target
  end
  return eval_fn, metadata
end
local details_of
details_of = function(rules, req, decision_cfg)
  if decision_cfg == nil then
    decision_cfg = nil
  end
  local effective_cfg = decision_cfg or (rules and rules.decision_cfg) or { }
  local continue_mode = effective_cfg.continue_to_next_rule
  local first_match_wins = true
  if effective_cfg.first_match_wins ~= nil then
    first_match_wins = not not effective_cfg.first_match_wins
  end
  local last_verdict, last_msg, last_rule_id, last_timeout, last_rule_desc, last_modifiers, last_condition_reason, last_allow_modifiers = nil, nil, nil, nil, nil, nil, nil, nil
  local response_rule_ids = { }
  local redirect_any, cname_target_any = false, nil
  for _index_0 = 1, #rules do
    local rule_fn = rules[_index_0]
    local verdict, msg, rule_id, rule_timeout, rule_desc, rule_modifiers, condition_reason, allow_modifiers, matched, has_on_response, redirects_destination, cname_target = rule_fn(req)
    if matched and has_on_response and rule_id then
      response_rule_ids[#response_rule_ids + 1] = rule_id
    end
    if matched and redirects_destination then
      redirect_any = true
      cname_target_any = cname_target or cname_target_any
    end
    if verdict ~= nil then
      if continue_mode or not first_match_wins then
        last_verdict, last_msg, last_rule_id, last_timeout, last_rule_desc, last_modifiers, last_condition_reason, last_allow_modifiers = verdict, msg, rule_id, rule_timeout, rule_desc, rule_modifiers, condition_reason, allow_modifiers
      else
        return verdict, msg, rule_id, rule_timeout, rule_desc, rule_modifiers, condition_reason, allow_modifiers, response_rule_ids, redirect_any, cname_target_any
      end
    end
  end
  if last_verdict ~= nil then
    return last_verdict, last_msg, last_rule_id, last_timeout, last_rule_desc, last_modifiers, last_condition_reason, last_allow_modifiers, response_rule_ids, redirect_any, cname_target_any
  end
  return false, "No matching rule (default deny)", nil, nil, nil, nil, nil, nil, response_rule_ids, redirect_any, cname_target_any
end
local compile_rules
compile_rules = function(cfg)
  local rules_cfg = cfg.rules or { }
  local out = { }
  out.rules_metadata = { }
  local used_ids = { }
  for idx, rule in ipairs(rules_cfg) do
    local eval_fn, metadata = compile_rule(cfg, rule, idx, used_ids)
    out[#out + 1] = eval_fn
    out.rules_metadata[idx] = metadata
  end
  out.decision_cfg = cfg.decision or { }
  out.on_response_by_id = { }
  for _, meta in ipairs(out.rules_metadata) do
    out.on_response_by_id[meta.rule_id] = meta.on_response or { }
  end
  return out
end
local decide
decide = function(rules, req, decision_cfg)
  if decision_cfg == nil then
    decision_cfg = nil
  end
  local verdict, msg, _, rule_desc
  verdict, msg, _, _, rule_desc = details_of(rules, req, decision_cfg)
  return verdict, msg, rule_desc
end
local decide_meta
decide_meta = function(rules, req, decision_cfg)
  if decision_cfg == nil then
    decision_cfg = nil
  end
  local verdict, msg, rule_id, rule_timeout, rule_desc, rule_modifiers, condition_reason, allow_modifiers, response_rule_ids, redirects_destination, cname_target = details_of(rules, req, decision_cfg)
  return {
    verdict = verdict,
    reason = msg,
    condition_reason = condition_reason,
    response_rule_ids = response_rule_ids or { },
    rule_id = rule_id,
    timeout = rule_timeout,
    description = rule_desc,
    modifiers = rule_modifiers or { },
    allow_modifiers = allow_modifiers or { },
    redirects_destination = redirects_destination or false,
    cname_target = cname_target
  }
end
local on_response_for
on_response_for = function(rules, rule_id)
  if not (rules and rule_id) then
    return { }
  end
  if rules.on_response_by_id then
    return rules.on_response_by_id[rule_id] or { }
  end
  for _, meta in ipairs((rules.rules_metadata or { })) do
    if meta.rule_id == rule_id then
      return meta.on_response or { }
    end
  end
  return { }
end
local on_response_for_many
on_response_for_many = function(rules, rule_ids)
  local out = { }
  local seen = { }
  if not (rules and type(rule_ids) == "table") then
    return out
  end
  for _, rid in ipairs(rule_ids) do
    local _continue_0 = false
    repeat
      if seen[rid] then
        _continue_0 = true
        break
      end
      seen[rid] = true
      local cbs = on_response_for(rules, rid)
      for _index_0 = 1, #cbs do
        local cb = cbs[_index_0]
        out[#out + 1] = cb
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return out
end
local apply_on_response
apply_on_response = function(on_response_cbs, dns_raw, reason, ctx_extra)
  if ctx_extra == nil then
    ctx_extra = nil
  end
  local ctx = {
    dns_raw = dns_raw,
    modified = false,
    explicit_allow = false,
    skip_nft = false,
    action_label = nil,
    reason = reason or ""
  }
  if type(ctx_extra) == "table" then
    for k, v in pairs(ctx_extra) do
      ctx[k] = v
    end
  end
  local _list_0 = (on_response_cbs or { })
  for _index_0 = 1, #_list_0 do
    local cb = _list_0[_index_0]
    cb(ctx)
  end
  ctx.inject_nft = ctx.explicit_allow or not ctx.skip_nft
  return ctx
end
local run_on_response
run_on_response = function(rules, rule_id_or_ids, dns_raw, reason, ctx_extra)
  if ctx_extra == nil then
    ctx_extra = nil
  end
  local callbacks
  if type(rule_id_or_ids) == "table" then
    callbacks = on_response_for_many(rules, rule_id_or_ids)
  else
    callbacks = on_response_for(rules, rule_id_or_ids)
  end
  return apply_on_response(callbacks, dns_raw, reason, ctx_extra)
end
return {
  compile_rule = compile_rule,
  compile_rules = compile_rules,
  decide = decide,
  decide_meta = decide_meta,
  on_response_for = on_response_for,
  apply_on_response = apply_on_response,
  run_on_response = run_on_response
}
