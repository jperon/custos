local sort
sort = table.sort
local unpack = unpack or table.unpack
local memo
memo = function(self)
  local tmp = {
    __mode = "kv"
  }
  setmetatable(tmp, tmp)
  return function(x)
    if not x then
      return self(x)
    end
    local r = tmp[x] or {
      self(x)
    }
    if x then
      tmp[x] = r
    end
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
local bidirmt_gen
bidirmt_gen = function()
  local _mem = setmetatable({ }, {
    __mode = "kv"
  })
  return function(self, val)
    do
      local _k = _mem[val]
      if _k then
        return _k
      end
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
local iter
local wrap
wrap = function(self)
  local _ = {
    __call = self,
    __index = iter
  }
  return setmetatable(_, _)
end
iter = {
  __call = function(self, t, step, i)
    if step == nil then
      step = 1
    end
    if i == nil then
      i = (step > 0 and step or #t)
    end
    i = i - step
    return wrap(function()
      i = i + step
      return t[i]
    end)
  end,
  any = function(self, fn)
    return self:getn(1, fn)
  end,
  each = function(self, fn)
    while true do
      do
        local v = self()
        if v then
          fn(v)
        else
          break
        end
      end
    end
    return self
  end,
  getn = function(self, n, fn)
    local i = 1
    while true do
      do
        local v = self()
        if v then
          if fn(v) then
            if i == n then
              return v
            end
            i = i + 1
          end
        else
          break
        end
      end
    end
  end,
  map = function(self, fn)
    return wrap(function()
      do
        local v = self()
        if v then
          return fn(v)
        end
      end
    end)
  end,
  imap = function(self, fn)
    local i = 0
    return wrap(function()
      do
        local v = self()
        if v then
          i = i + 1
          return fn(v, i)
        end
      end
    end)
  end,
  filter = function(self, fn)
    return wrap(function()
      while true do
        do
          local v = self()
          if v then
            if fn(v) then
              return v
            end
          else
            return nil
          end
        end
      end
    end)
  end,
  take = function(self, n)
    local i = 0
    return wrap(function()
      i = i + 1
      if i <= n then
        return self()
      end
    end)
  end,
  toarray = function(self)
    local t = { }
    while true do
      do
        local v = self()
        if v then
          t[#t + 1] = v
        else
          break
        end
      end
    end
    return t
  end,
  reduce = function(self, fn, initial)
    local accum = initial or self()
    for v in self do
      accum = fn(accum, v)
    end
    return accum
  end
}
iter.__index = iter
setmetatable(iter, iter)
local generate
generate = function(fn)
  return wrap(function()
    return fn()
  end)
end
local range
range = function(self, max, step)
  step = step or 1
  local i = max and self - step or 0
  max = max or self
  return wrap(function()
    i = i + step
    if i <= max then
      return i
    end
  end)
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
local _ = nil
local protected
protected = function(fn, op)
  local leak_debug = _ and _.leak_debug
  return function(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
    local ok
    ok, a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z = xpcall((function()
      return fn(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z)
    end), function(err)
      print(err)
      if leak_debug then
        print(debug.traceback())
      end
      if op then
        return op()
      end
    end)
    if ok then
      return a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, q, r, s, t, u, v, w, x, y, z
    end
  end
end
_ = {
  bidirectional = bidirectional,
  memo = memo,
  memoN = memoN,
  iter = iter,
  wrap = wrap,
  range = range,
  opairs = opairs,
  generate = generate,
  zero_indexed = zero_indexed,
  protected = protected,
  __index = function(_, k)
    local fn
    fn = function(self, ...)
      local o = (type(self) == 'table' and iter or wrap)(self)
      return o[k](o, ...)
    end
    _[k] = fn
    return fn
  end
}
return setmetatable(_, _)
