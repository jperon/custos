--- src/filter/rule_id.moon
--- Centralized rule ID generation - single source of truth for rule naming
--- This module ensures consistent rule_id generation across all components:
--- - compiler (nft_compiler.moon, compiler_api.moon)
--- - auth server (auth/server.moon)
--- - DNS workers (worker_questions.moon, worker_responses.moon)

--- Translitère les caractères accentués vers leur équivalent ASCII.
--- @tparam string raw Chaîne brute
--- @treturn string Chaîne translitérée, espaces normalisés
sanitize_ascii = (raw) ->
  return "" unless raw
  s = tostring raw
  replacements = {
    {"À", "A"}, {"Á", "A"}, {"Â", "A"}, {"Ã", "A"}, {"Ä", "A"}, {"Å", "A"}
    {"à", "a"}, {"á", "a"}, {"â", "a"}, {"ã", "a"}, {"ä", "a"}, {"å", "a"}
    {"È", "E"}, {"É", "E"}, {"Ê", "E"}, {"Ë", "E"}
    {"è", "e"}, {"é", "e"}, {"ê", "e"}, {"ë", "e"}
    {"Ì", "I"}, {"Í", "I"}, {"Î", "I"}, {"Ï", "I"}
    {"ì", "i"}, {"í", "i"}, {"î", "i"}, {"ï", "i"}
    {"Ò", "O"}, {"Ó", "O"}, {"Ô", "O"}, {"Õ", "O"}, {"Ö", "O"}
    {"ò", "o"}, {"ó", "o"}, {"ô", "o"}, {"õ", "o"}, {"ö", "o"}
    {"Ù", "U"}, {"Ú", "U"}, {"Û", "U"}, {"Ü", "U"}
    {"ù", "u"}, {"ú", "u"}, {"û", "u"}, {"ü", "u"}
    {"Ý", "Y"}, {"Ÿ", "Y"}, {"ý", "y"}, {"ÿ", "y"}
    {"Ç", "C"}, {"ç", "c"}, {"Ñ", "N"}, {"ñ", "n"}
    {"ß", "ss"}, {"æ", "ae"}, {"Æ", "AE"}, {"œ", "oe"}, {"Œ", "OE"}
  }
  for _, pair in ipairs replacements
    s = s\gsub pair[1], pair[2]
  out = {}
  for i = 1, #s
    b = s\byte i
    if b >= 32 and b <= 126 and b != 34 and b != 92
      out[#out + 1] = string.char b
    elseif b == 9 or b == 10 or b == 13 or b == 34 or b == 92
      out[#out + 1] = " "
  sanitized = table.concat(out, "")\gsub "%s+", " "
  sanitized\match "^%s*(.-)%s*$"

--- Normalise une chaîne en identifiant ASCII minuscule (pour noms de règles).
--- Translitère d'abord les accents avant de remplacer les caractères non-ASCII.
--- @tparam string raw Chaîne brute
--- @treturn string Identifiant normalisé (max 128 chars)
sanitize_id = (raw) ->
  s = sanitize_ascii(raw)\lower!
  s = s\gsub "[^a-z0-9_%-]+", "_"
  s = s\gsub "_+", "_"
  s = s\gsub "^_+", ""
  s = s\gsub "_+$", ""
  s = s\gsub "%-+", "_"
  if #s > 128
    s = s\sub 1, 128
  s

--- Generate a stable rule_id from a rule configuration
--- @tparam table rule Rule configuration with rule_id or description
--- @tparam number idx Rule index (fallback)
--- @treturn string rule_id in format "r_<base>" or "r_<idx>"
generate = (rule, idx) ->
  if rule and rule.rule_id and tostring(rule.rule_id)\match "%S"
    base = sanitize_id rule.rule_id
    return "r_#{base}" if #base > 0
  if rule and rule.description and tostring(rule.description)\match "%S"
    base = sanitize_id rule.description
    return "r_#{base}" if #base > 0
  "r_#{idx}"

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

{ :generate, :generate_unique, :sanitize_id, :sanitize_ascii }
