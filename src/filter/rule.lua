local compile_rule
compile_rule = function(cfg, rule_cfg)
  local conditions = { }
  for name, args in pairs((rule_cfg.conditions or { })) do
    local ok, factory_loader = pcall(require, "filter.conditions." .. tostring(name))
    if not (ok) then
      error("Condition inconnue '" .. tostring(name) .. "': " .. tostring(factory_loader))
    end
    local factory = factory_loader(cfg)
    conditions[#conditions + 1] = factory(args)
  end
  local actions = { }
  for _, action_name in ipairs((rule_cfg.actions or { })) do
    local ok, factory_loader = pcall(require, "filter.actions." .. tostring(action_name))
    if not (ok) then
      error("Action inconnue '" .. tostring(action_name) .. "': " .. tostring(factory_loader))
    end
    actions[#actions + 1] = (factory_loader(cfg))(rule_cfg)
  end
  return function(req)
    for _, cond in ipairs(conditions) do
      local ok, reason = cond(req)
      if not (ok) then
        return nil, reason
      end
    end
    local verdict, msg
    for _, action in ipairs(actions) do
      local v, m = action(req)
      if v ~= nil and verdict == nil then
        verdict = v
        msg = m
      elseif v == nil and m then
        msg = msg or m
      end
    end
    return verdict, msg
  end
end
local compile_rules
compile_rules = function(cfg)
  local rules = { }
  for _, rule_cfg in ipairs((cfg.rules or { })) do
    rules[#rules + 1] = compile_rule(cfg, rule_cfg)
  end
  return rules
end
local decide
decide = function(rules, req)
  for _, rule_fn in ipairs(rules) do
    local verdict, msg = rule_fn(req)
    if verdict ~= nil then
      return verdict, msg
    end
  end
  return false, "No matching rule (default deny)"
end
return {
  compile_rules = compile_rules,
  decide = decide
}
