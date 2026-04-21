local concat = table.concat
local remove = table.remove
local insert = table.insert
local render_tag
render_tag = function(tag, ...)
  local children = { }
  local attrs = { }
  for i = 1, select("#", ...) do
    local arg = select(i, ...)
    local t = type(arg)
    local _exp_0 = t
    if "table" == _exp_0 then
      while #arg > 0 do
        insert(children, remove(arg, 1))
      end
      for k, v in pairs(arg) do
        insert(attrs, " " .. tostring(k) .. "=\"" .. tostring(v) .. "\"")
      end
    elseif "function" == _exp_0 then
      insert(children, arg())
    elseif "string" == _exp_0 or "number" == _exp_0 then
      insert(children, arg)
    end
  end
  local attr_html = concat(attrs)
  if #children == 0 then
    return "<" .. tostring(tag) .. tostring(attr_html) .. "/>"
  else
    return "<" .. tostring(tag) .. tostring(attr_html) .. ">" .. tostring(concat(children, '\n')) .. "</" .. tostring(tag) .. ">"
  end
end
local html = { }
setmetatable(html, {
  __index = function(self, k)
    return function(...)
      return render_tag(k, ...)
    end
  end
})
return html
