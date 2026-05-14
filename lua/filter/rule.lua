local compiler_api = require("filter.compiler_api")
local compile_rule
compile_rule = function(cfg, rule, idx, used_ids)
  if used_ids == nil then
    used_ids = nil
  end
  local conditions = { }
  local conditions_meta = { }
  local _list_0 = (rule.conditions or { })
  for _index_0 = 1, #_list_0 do
    local condition = _list_0[_index_0]
    local name, args = nil, nil
    if type(condition) == "table" then
      for _name, _args in pairs(condition) do
        name, args = _name, _args
      end
    else
      name = condition
    end
    local cond_factory, err = compiler_api.load_condition(name)
    if not (cond_factory) then
      error("Condition inconnue '" .. tostring(name) .. "': " .. tostring(err))
    end
    local cond_obj = cond_factory(cfg)(args)
    conditions[#conditions + 1] = cond_obj.eval
    conditions_meta[#conditions_meta + 1] = {
      name = name,
      args = args,
      capabilities = cond_obj.capabilities,
      worker_only = compiler_api.compute_worker_only(cond_obj),
      compile_nft = cond_obj.compile_nft,
      creates_dynamic_scope = cond_obj.creates_dynamic_scope
    }
  end
  local actions = { }
  local actions_meta = { }
  local _list_1 = (rule.actions or { })
  for _index_0 = 1, #_list_1 do
    local action_name = _list_1[_index_0]
    local action_factory, err = compiler_api.load_action(action_name)
    if not (action_factory) then
      error("Action inconnue '" .. tostring(action_name) .. "': " .. tostring(err))
    end
    local action_obj = action_factory(cfg)(rule)
    actions[#actions + 1] = action_obj.eval
    actions_meta[#actions_meta + 1] = {
      name = action_name,
      capabilities = action_obj.capabilities,
      worker_only = compiler_api.compute_worker_only(action_obj),
      compile_nft = action_obj.compile_nft,
      verdict = action_obj.verdict
    }
  end
  local rule_desc = rule.description or "rule_" .. tostring(idx)
  local rule_id = compiler_api.unique_rule_id(rule, idx, used_ids)
  local rule_timeout = rule.nft_timeout or (cfg.nft and cfg.nft.ip_timeout) or "2m"
  local metadata = {
    rule_id = rule_id,
    description = rule_desc,
    timeout = rule_timeout,
    conditions = conditions_meta,
    actions = actions_meta,
    worker_only = false
  }
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
  metadata.creates_dynamic_scope = false
  for _index_0 = 1, #conditions_meta do
    local cond = conditions_meta[_index_0]
    if cond.creates_dynamic_scope then
      metadata.creates_dynamic_scope = true
      break
    end
  end
  local eval_fn
  eval_fn = function(req)
    for _index_0 = 1, #conditions do
      local cond = conditions[_index_0]
      local ok, reason = cond(req)
      if not (ok) then
        return nil, reason
      end
    end
    local verdict, msg
    for _index_0 = 1, #actions do
      local action = actions[_index_0]
      local v, m = action(req)
      if v ~= nil and verdict == nil then
        verdict = v
        msg = m
      elseif v == nil and m then
        msg = msg or m
      end
    end
    return verdict, msg, rule_id, rule_timeout, rule_desc
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
  local last_verdict, last_msg, last_rule_id, last_timeout, last_rule_desc = nil, nil, nil, nil, nil
  for _index_0 = 1, #rules do
    local rule_fn = rules[_index_0]
    local verdict, msg, rule_id, rule_timeout, rule_desc = rule_fn(req)
    if verdict ~= nil then
      if continue_mode or not first_match_wins then
        last_verdict, last_msg, last_rule_id, last_timeout, last_rule_desc = verdict, msg, rule_id, rule_timeout, rule_desc
      else
        return verdict, msg, rule_id, rule_timeout, rule_desc
      end
    end
  end
  if last_verdict ~= nil then
    return last_verdict, last_msg, last_rule_id, last_timeout, last_rule_desc
  end
  return false, "No matching rule (default deny)", nil, nil, nil
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
  local verdict, msg, rule_id, rule_timeout, rule_desc = details_of(rules, req, decision_cfg)
  return {
    verdict = verdict,
    reason = msg,
    rule_id = rule_id,
    timeout = rule_timeout,
    description = rule_desc
  }
end
return {
  compile_rule = compile_rule,
  compile_rules = compile_rules,
  decide = decide,
  decide_meta = decide_meta
}
