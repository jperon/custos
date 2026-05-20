local sanitize_ascii
sanitize_ascii = function(raw)
  if not (raw) then
    return ""
  end
  local s = tostring(raw)
  local replacements = {
    {
      "À",
      "A"
    },
    {
      "Á",
      "A"
    },
    {
      "Â",
      "A"
    },
    {
      "Ã",
      "A"
    },
    {
      "Ä",
      "A"
    },
    {
      "Å",
      "A"
    },
    {
      "à",
      "a"
    },
    {
      "á",
      "a"
    },
    {
      "â",
      "a"
    },
    {
      "ã",
      "a"
    },
    {
      "ä",
      "a"
    },
    {
      "å",
      "a"
    },
    {
      "È",
      "E"
    },
    {
      "É",
      "E"
    },
    {
      "Ê",
      "E"
    },
    {
      "Ë",
      "E"
    },
    {
      "è",
      "e"
    },
    {
      "é",
      "e"
    },
    {
      "ê",
      "e"
    },
    {
      "ë",
      "e"
    },
    {
      "Ì",
      "I"
    },
    {
      "Í",
      "I"
    },
    {
      "Î",
      "I"
    },
    {
      "Ï",
      "I"
    },
    {
      "ì",
      "i"
    },
    {
      "í",
      "i"
    },
    {
      "î",
      "i"
    },
    {
      "ï",
      "i"
    },
    {
      "Ò",
      "O"
    },
    {
      "Ó",
      "O"
    },
    {
      "Ô",
      "O"
    },
    {
      "Õ",
      "O"
    },
    {
      "Ö",
      "O"
    },
    {
      "ò",
      "o"
    },
    {
      "ó",
      "o"
    },
    {
      "ô",
      "o"
    },
    {
      "õ",
      "o"
    },
    {
      "ö",
      "o"
    },
    {
      "Ù",
      "U"
    },
    {
      "Ú",
      "U"
    },
    {
      "Û",
      "U"
    },
    {
      "Ü",
      "U"
    },
    {
      "ù",
      "u"
    },
    {
      "ú",
      "u"
    },
    {
      "û",
      "u"
    },
    {
      "ü",
      "u"
    },
    {
      "Ý",
      "Y"
    },
    {
      "Ÿ",
      "Y"
    },
    {
      "ý",
      "y"
    },
    {
      "ÿ",
      "y"
    },
    {
      "Ç",
      "C"
    },
    {
      "ç",
      "c"
    },
    {
      "Ñ",
      "N"
    },
    {
      "ñ",
      "n"
    },
    {
      "ß",
      "ss"
    },
    {
      "æ",
      "ae"
    },
    {
      "Æ",
      "AE"
    },
    {
      "œ",
      "oe"
    },
    {
      "Œ",
      "OE"
    }
  }
  for _, pair in ipairs(replacements) do
    s = s:gsub(pair[1], pair[2])
  end
  local out = { }
  for i = 1, #s do
    local b = s:byte(i)
    if b >= 32 and b <= 126 and b ~= 34 and b ~= 92 then
      out[#out + 1] = string.char(b)
    elseif b == 9 or b == 10 or b == 13 or b == 34 or b == 92 then
      out[#out + 1] = " "
    end
  end
  local sanitized = table.concat(out, ""):gsub("%s+", " ")
  return sanitized:match("^%s*(.-)%s*$")
end
local sanitize_id
sanitize_id = function(raw)
  local s = sanitize_ascii(raw):lower()
  s = s:gsub("[^a-z0-9_%-]+", "_")
  s = s:gsub("_+", "_")
  s = s:gsub("^_+", "")
  s = s:gsub("_+$", "")
  s = s:gsub("%-+", "_")
  if #s > 128 then
    s = s:sub(1, 128)
  end
  return s
end
local generate
generate = function(rule, idx)
  if rule and rule.rule_id and tostring(rule.rule_id):match("%S") then
    local base = sanitize_id(rule.rule_id)
    if #base > 0 then
      return "r_" .. tostring(base)
    end
  end
  if rule and rule.description and tostring(rule.description):match("%S") then
    local base = sanitize_id(rule.description)
    if #base > 0 then
      return "r_" .. tostring(base)
    end
  end
  return "r_" .. tostring(idx)
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
  sanitize_id = sanitize_id,
  sanitize_ascii = sanitize_ascii
}
