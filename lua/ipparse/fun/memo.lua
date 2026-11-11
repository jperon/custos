local unpack = unpack or table.unpack
local memo
memo = function(self)
  local tmp = {
    __mode = "kv"
  }
  setmetatable(tmp, tmp)
  return function(x)
    if x == nil then
      return self(x)
    end
    local r = tmp[x] or {
      self(x)
    }
    tmp[x] = r
    return unpack(r)
  end
end
local memoN
memoN = function(self)
  local _nil = { }
  local tmp = {
    __mode = "kv"
  }
  setmetatable(tmp, tmp)
  return function(...)
    local t, s = tmp, select("#", ...)
    local levels = {
      s,
      ...
    }
    local ref, r
    for i = 1, s + 1 do
      ref = levels[i]
      if ref == nil then
        ref = _nil
      end
      r = t[ref]
      if i <= s then
        r = r or setmetatable({ }, tmp)
        t[ref] = r
        t = r
      end
    end
    if r == nil then
      r = {
        self(...)
      }
      t[ref] = r
    end
    return unpack(r)
  end
end
return {
  memo = memo,
  memoN = memoN
}
