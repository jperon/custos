local bit = {
  band = function(...)
    local n = select("#", ...)
    if n <= 1 then
      return ...
    end
    local a, b = ...
    if n == 2 then
      return a & b
    end
    local r = a
    for i = 2, n do
      r = r & (select(i, ...))
    end
    return r
  end,
  bor = function(...)
    local n = select("#", ...)
    if n <= 1 then
      return ...
    end
    local a, b = ...
    if n == 2 then
      return a | b
    end
    local r = a
    for i = 2, n do
      r = r | (select(i, ...))
    end
    return r
  end,
  bxor = function(...)
    local n = select("#", ...)
    if n <= 1 then
      return ...
    end
    local a, b = ...
    if n == 2 then
      return (a | b) & (~(a & b))
    end
    local r = a
    for i = 2, n do
      local v = select(i, ...)
      r = (r | v) & (~(r & v))
    end
    return r
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
    return a >> n
  end
}
return bit
