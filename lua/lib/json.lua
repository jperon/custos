local EscapeMap = {
  ['"'] = '\\"',
  ["\\"] = "\\\\",
  ["\b"] = "\\b",
  ["\f"] = "\\f",
  ["\n"] = "\\n",
  ["\r"] = "\\r",
  ["\t"] = "\\t"
}
local encode_string
encode_string = function(s)
  local escaped = s:gsub('[%c"\\]', function(c)
    return EscapeMap[c] or string.format("\\u%04x", c:byte())
  end)
  return '"' .. escaped .. '"'
end
local is_array
is_array = function(t)
  local n = #t
  if n == 0 and next(t) ~= nil then
    return false
  end
  local count = 0
  for k in pairs(t) do
    if not (type(k) == "number") then
      return false
    end
    if not (k >= 1 and k <= n and math.floor(k) == k) then
      return false
    end
    count = count + 1
  end
  return count == n
end
local encode_value = nil
encode_value = function(v, stack)
  local _exp_0 = type(v)
  if "nil" == _exp_0 then
    return "null"
  elseif "boolean" == _exp_0 then
    return v and "true" or "false"
  elseif "number" == _exp_0 then
    return tostring(v)
  elseif "string" == _exp_0 then
    return encode_string(v)
  elseif "table" == _exp_0 then
    if stack[v] then
      return "null"
    end
    stack[v] = true
    local out = nil
    if is_array(v) then
      local parts
      do
        local _accum_0 = { }
        local _len_0 = 1
        for _index_0 = 1, #v do
          local item = v[_index_0]
          _accum_0[_len_0] = (encode_value(item, stack))
          _len_0 = _len_0 + 1
        end
        parts = _accum_0
      end
      out = "[" .. table.concat(parts, ",") .. "]"
    else
      local keys
      do
        local _accum_0 = { }
        local _len_0 = 1
        for k in pairs(v) do
          _accum_0[_len_0] = k
          _len_0 = _len_0 + 1
        end
        keys = _accum_0
      end
      table.sort(keys, function(a, b)
        return tostring(a) < tostring(b)
      end)
      local parts = { }
      for _index_0 = 1, #keys do
        local k = keys[_index_0]
        parts[#parts + 1] = encode_string(tostring(k)) .. ":" .. (encode_value(v[k], stack))
      end
      out = "{" .. table.concat(parts, ",") .. "}"
    end
    stack[v] = nil
    return out
  else
    return "null"
  end
end
local encode
encode = function(v)
  return encode_value(v, { })
end
local utf8_char
utf8_char = function(cp)
  if cp < 0x80 then
    return string.char(cp)
  elseif cp < 0x800 then
    return string.char(0xC0 + math.floor(cp / 0x40), 0x80 + cp % 0x40)
  elseif cp < 0x10000 then
    return string.char(0xE0 + math.floor(cp / 0x1000), 0x80 + math.floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
  else
    return string.char(0xF0 + math.floor(cp / 0x40000), 0x80 + math.floor(cp / 0x1000) % 0x40, 0x80 + math.floor(cp / 0x40) % 0x40, 0x80 + cp % 0x40)
  end
end
local fail
fail = function(msg, pos)
  return error("json: " .. tostring(msg) .. " (position " .. tostring(pos) .. ")", 0)
end
local skip_ws
skip_ws = function(s, i)
  while true do
    local c = s:sub(i, i)
    if c == " " or c == "\t" or c == "\n" or c == "\r" then
      i = i + 1
    else
      return i
    end
  end
end
local parse_string = nil
local parse_number = nil
local parse_array = nil
local parse_object = nil
local parse_value = nil
parse_string = function(s, i)
  local buf = { }
  i = i + 1
  while true do
    local jq = s:find('"', i, true)
    local jb = s:find("\\", i, true)
    local j = jq
    if jb and (not j or jb < j) then
      j = jb
    end
    if not (j) then
      fail("chaîne non terminée", i)
    end
    buf[#buf + 1] = s:sub(i, j - 1)
    local c = s:sub(j, j)
    if c == '"' then
      return table.concat(buf), j + 1
    end
    local e = s:sub(j + 1, j + 1)
    local _exp_0 = e
    if '"' == _exp_0 then
      buf[#buf + 1] = '"'
    elseif "\\" == _exp_0 then
      buf[#buf + 1] = "\\"
    elseif "/" == _exp_0 then
      buf[#buf + 1] = "/"
    elseif "b" == _exp_0 then
      buf[#buf + 1] = "\b"
    elseif "f" == _exp_0 then
      buf[#buf + 1] = "\f"
    elseif "n" == _exp_0 then
      buf[#buf + 1] = "\n"
    elseif "r" == _exp_0 then
      buf[#buf + 1] = "\r"
    elseif "t" == _exp_0 then
      buf[#buf + 1] = "\t"
    elseif "u" == _exp_0 then
      local hex = s:sub(j + 2, j + 5)
      if not (hex and hex:match("^%x%x%x%x$")) then
        fail("échappement unicode invalide", j)
      end
      local cp = tonumber(hex, 16)
      if cp >= 0xD800 and cp <= 0xDBFF and s:sub(j + 6, j + 7) == "\\u" then
        local hex2 = s:sub(j + 8, j + 11)
        if hex2 and hex2:match("^%x%x%x%x$") then
          local cp2 = tonumber(hex2, 16)
          if cp2 >= 0xDC00 and cp2 <= 0xDFFF then
            cp = 0x10000 + (cp - 0xD800) * 0x400 + (cp2 - 0xDC00)
            j = j + 6
          end
        end
      end
      buf[#buf + 1] = utf8_char(cp)
      j = j + 4
    else
      fail("échappement invalide", j)
    end
    i = j + 2
  end
end
parse_number = function(s, i)
  local body = s:match("^-?%d+", i)
  if not (body) then
    fail("nombre invalide", i)
  end
  local num = body
  local j = i + #body
  if s:sub(j, j) == "." then
    local frac = s:match("^%.%d+", j)
    if not (frac) then
      fail("nombre invalide", j)
    end
    num = num .. frac
    j = j + #frac
  end
  if s:sub(j, j) == "e" or s:sub(j, j) == "E" then
    local exp = s:match("^[eE][+-]?%d+", j)
    if not (exp) then
      fail("exposant invalide", j)
    end
    num = num .. exp
    j = j + #exp
  end
  local n = tonumber(num)
  if not (n) then
    fail("nombre invalide", i)
  end
  return n, j
end
parse_array = function(s, i)
  local out = { }
  i = skip_ws(s, i + 1)
  if s:sub(i, i) == "]" then
    return out, i + 1
  end
  while true do
    local v
    v, i = parse_value(s, i)
    out[#out + 1] = v
    i = skip_ws(s, i)
    local c = s:sub(i, i)
    if c == "," then
      i = skip_ws(s, i + 1)
    elseif c == "]" then
      return out, i + 1
    else
      fail("tableau invalide", i)
    end
  end
end
parse_object = function(s, i)
  local out = { }
  i = skip_ws(s, i + 1)
  if s:sub(i, i) == "}" then
    return out, i + 1
  end
  while true do
    if not (s:sub(i, i) == '"') then
      fail("clé attendue", i)
    end
    local k
    k, i = parse_string(s, i)
    i = skip_ws(s, i)
    if not (s:sub(i, i) == ":") then
      fail("':' attendu", i)
    end
    local v
    v, i = parse_value(s, skip_ws(s, i + 1))
    out[k] = v
    i = skip_ws(s, i)
    local c = s:sub(i, i)
    if c == "," then
      i = skip_ws(s, i + 1)
    elseif c == "}" then
      return out, i + 1
    else
      fail("objet invalide", i)
    end
  end
end
parse_value = function(s, i)
  i = skip_ws(s, i)
  local c = s:sub(i, i)
  if c == '"' then
    return parse_string(s, i)
  elseif c == "{" then
    return parse_object(s, i)
  elseif c == "[" then
    return parse_array(s, i)
  elseif c == "t" then
    if not (s:sub(i, i + 3) == "true") then
      fail("littéral invalide", i)
    end
    return true, i + 4
  elseif c == "f" then
    if not (s:sub(i, i + 4) == "false") then
      fail("littéral invalide", i)
    end
    return false, i + 5
  elseif c == "n" then
    if not (s:sub(i, i + 3) == "null") then
      fail("littéral invalide", i)
    end
    return nil, i + 4
  else
    if c == "" then
      fail("valeur invalide", i)
    end
    return parse_number(s, i)
  end
end
local decode
decode = function(s)
  if not (type(s) == "string") then
    fail("entrée non textuelle", 0)
  end
  local v, i = parse_value(s, 1)
  i = skip_ws(s, i)
  if i <= #s then
    fail("caractères en trop", i)
  end
  return v
end
return {
  encode = encode,
  decode = decode
}
