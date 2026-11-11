local bit = {
  band = function(a, b, c, ...)
    if c == nil then
      if b == nil then
        return a
      else
        return a & b
      end
    else
      local r = a & b & c
      local n = select("#", ...)
      for i = 1, n do
        r = r & (select(i, ...))
      end
      return r
    end
  end,
  bor = function(a, b, c, ...)
    if c == nil then
      if b == nil then
        return a
      else
        return a | b
      end
    else
      local r = a | b | c
      local n = select("#", ...)
      for i = 1, n do
        r = r | (select(i, ...))
      end
      return r
    end
  end,
  bxor = function(a, b, c, ...)
    if c == nil then
      if b == nil then
        return a
      else
        return (a | b) & (~(a & b))
      end
    else
      local r = (a | b) & (~(a & b))
      r = (r | c) & (~(r & c))
      local n = select("#", ...)
      for i = 1, n do
        local v = select(i, ...)
        r = (r | v) & (~(r & v))
      end
      return r
    end
  end,
  bnot = function(a)
    return ~a
  end,
  lshift = function(a, n)
    return a << n
  end,
  rshift = function(a, n)
    return a >> n
  end,
  arshift = function(a, n)
    if a >= 0 then
      return a >> n
    else
      return ~((~a) >> n)
    end
  end
}
return bit
