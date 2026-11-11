local sort
sort = table.sort
local bidirmt_gen
bidirmt_gen = function()
  local _mem = setmetatable({ }, {
    __mode = "kv"
  })
  return function(self, val)
    local _k = _mem[val]
    if _k and rawget(self, _k) == val then
      return _k
    end
    for k, v in pairs(self) do
      if v == val then
        _mem[val] = k
        return k
      end
    end
  end
end
local bidirectional
bidirectional = function(self)
  return setmetatable(self, {
    __index = bidirmt_gen()
  })
end
local zero_indexed
zero_indexed = function(self)
  for i = 0, #self do
    self[i] = self[i + 1]
  end
  return self
end
local opairs
opairs = function(self, f)
  if f == nil then
    f = function(a, b)
      if type(a) == type(b) then
        return a < b
      else
        return tostring(a) < tostring(b)
      end
    end
  end
  local keys, i = { }, 1
  for k in pairs(self) do
    keys[i] = k
    i = i + 1
  end
  sort(keys, f)
  i = 0
  return function()
    i = i + 1
    return keys[i], self[keys[i]]
  end
end
return {
  bidirectional = bidirectional,
  zero_indexed = zero_indexed,
  opairs = opairs
}
