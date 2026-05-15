local sanitize_id
sanitize_id = function(s)
  if not (s) then
    return ""
  end
  s = tostring(s)
  s = s:gsub("[^%w%-_]", "_")
  s = s:gsub("^_+", "")
  s = s:gsub("_+$", "")
  s = s:gsub("%-+", "_")
  if #s > 40 then
    s = s:sub(1, 40)
  end
  return s
end
local generate
generate = function(rule, idx)
  if rule and rule.rule_id and tostring(rule.rule_id):match("%S") then
    local base = sanitize_id(rule.rule_id)
    if #base > 0 then
      return "rule_" .. tostring(base)
    end
  end
  if rule and rule.description and tostring(rule.description):match("%S") then
    local base = sanitize_id(rule.description)
    if #base > 0 then
      return "rule_" .. tostring(base)
    end
  end
  return "rule_" .. tostring(idx)
end
local generate_unique
generate_unique = function(rule, idx, used_ids)
  local base = generate(rule, idx)
  local rid = base
  local n = 1
  while used_ids and used_ids[rid] do
    n = n + 1
    rid = tostring(base) .. "_" .. tostring(n)
  end
  if used_ids then
    used_ids[rid] = true
  end
  return rid
end
return {
  generate = generate,
  generate_unique = generate_unique,
  sanitize_id = sanitize_id
}
