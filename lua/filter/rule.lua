local compile_rule
compile_rule = function(cfg, rule, idx)
  local conditions = { }
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
    local ok, factory_loader = pcall(require, "filter.conditions." .. tostring(name))
    if not (ok) then
      error("Condition inconnue '" .. tostring(name) .. "': " .. tostring(factory_loader))
    end
    local factory = factory_loader(cfg)
    conditions[#conditions + 1] = factory(args)
  end
  local actions = { }
  local _list_1 = (rule.actions or { })
  for _index_0 = 1, #_list_1 do
    local action = _list_1[_index_0]
    local ok, factory_loader = pcall(require, "filter.actions." .. tostring(action))
    if not (ok) then
      error("Action inconnue '" .. tostring(action) .. "': " .. tostring(factory_loader))
    end
    actions[#actions + 1] = (factory_loader(cfg))(rule)
  end
  local rule_desc = rule.description or "rule_" .. tostring(idx)
  local rule_id = rule.rule_id or "rule_" .. tostring(idx)
  local rule_timeout = rule.nft_timeout or (cfg.nft and cfg.nft.ip_timeout) or "2m"
  return function(req)
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
  for idx, rule in ipairs(rules_cfg) do
    out[#out + 1] = compile_rule(cfg, rule, idx)
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
  compile_rules = compile_rules,
  decide = decide,
  decide_meta = decide_meta
}
