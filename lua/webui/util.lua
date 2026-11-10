local esc
esc = function(s)
  if s == nil then
    return ""
  end
  s = tostring(s)
  return (s:gsub("[&<>\"']", {
    ["&"] = "&amp;",
    ["<"] = "&lt;",
    [">"] = "&gt;",
    ['"'] = "&quot;",
    ["'"] = "&#39;"
  }))
end
local parse_form
parse_form = function(body)
  if not (body) then
    return { }
  end
  local out = { }
  local dec
  dec = function(s)
    return (s:gsub("%%(%x%x)", function(h)
      return string.char(tonumber(h, 16))
    end)):gsub("+", " ")
  end
  for k, v in body:gmatch("([^&=]+)=([^&]*)") do
    out[dec(k)] = dec(v)
  end
  return out
end
return {
  esc = esc,
  parse_form = parse_form
}
