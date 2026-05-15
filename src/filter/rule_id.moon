--- src/filter/rule_id.moon
--- Centralized rule ID generation - single source of truth for rule naming
--- This module ensures consistent rule_id generation across all components:
--- - compiler (nft_compiler.moon, compiler_api.moon)
--- - auth server (auth/server.moon)
--- - DNS workers (worker_questions.moon, worker_responses.moon)

sanitize_id = (s) ->
  return "" unless s
  s = tostring s
  s = s\gsub "[^%w%-_]", "_"
  s = s\gsub "^_+", ""
  s = s\gsub "_+$", ""
  s = s\gsub "%-+", "_"
  if #s > 40
    s = s\sub 1, 40
  s

--- Generate a stable rule_id from a rule configuration
--- @tparam table rule Rule configuration with rule_id or description
--- @tparam number idx Rule index (fallback)
--- @treturn string rule_id in format "rule_<base>" or "rule_<idx>"
generate = (rule, idx) ->
  if rule and rule.rule_id and tostring(rule.rule_id)\match "%S"
    base = sanitize_id rule.rule_id
    return "rule_#{base}" if #base > 0
  if rule and rule.description and tostring(rule.description)\match "%S"
    base = sanitize_id rule.description
    return "rule_#{base}" if #base > 0
  "rule_#{idx}"

--- Generate a unique rule_id, ensuring no collisions
--- @tparam table rule Rule configuration
--- @tparam number idx Rule index
--- @tparam table used_ids Set of already-used rule_ids
--- @treturn string Unique rule_id
generate_unique = (rule, idx, used_ids) ->
  base = generate rule, idx
  rid = base
  n = 1
  while used_ids and used_ids[rid]
    n += 1
    rid = "#{base}_#{n}"
  used_ids[rid] = true if used_ids
  rid

{ :generate, :generate_unique, :sanitize_id }
