local compile_rule
compile_rule = function(cfg, rule)
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
  local rule_desc = rule.description or rule._desc or rule.name or rule.type
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
    return verdict, msg, rule_desc
  end
end
local compile_rules
compile_rules = function(cfg)
  local _accum_0 = { }
  local _len_0 = 1
  local _list_0 = (cfg.rules or { })
  for _index_0 = 1, #_list_0 do
    local rule = _list_0[_index_0]
    _accum_0[_len_0] = compile_rule(cfg, rule)
    _len_0 = _len_0 + 1
  end
  return _accum_0
end
local decide
decide = function(rules, req)
  for _index_0 = 1, #rules do
    local rule_fn = rules[_index_0]
    local verdict, msg, rule_desc = rule_fn(req)
    if verdict ~= nil then
      return verdict, msg, rule_desc
    end
  end
  return false, "No matching rule (default deny)", nil
end
return {
  compile_rules = compile_rules,
  decide = decide
}
