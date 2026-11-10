local TWO32 = 0x100000000
local MASK32 = 0xFFFFFFFF
local SIGN32 = 0x80000000
local pow2
pow2 = function(n)
  local p = 1
  for _ = 1, n do
    p = p * 2
  end
  return p
end
local to_u32
to_u32 = function(n)
  return math.floor(n % TWO32)
end
local to_s32
to_s32 = function(u)
  if u >= SIGN32 then
    return u - TWO32
  end
  return u
end
local and2
and2 = function(a, b)
  local result, weight = 0, 1
  for _ = 1, 32 do
    if a % 2 == 1 and b % 2 == 1 then
      result = result + weight
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    weight = weight * 2
  end
  return result
end
local or2
or2 = function(a, b)
  local result, weight = 0, 1
  for _ = 1, 32 do
    if a % 2 == 1 or b % 2 == 1 then
      result = result + weight
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    weight = weight * 2
  end
  return result
end
local xor2
xor2 = function(a, b)
  local result, weight = 0, 1
  for _ = 1, 32 do
    if (a % 2) ~= (b % 2) then
      result = result + weight
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    weight = weight * 2
  end
  return result
end
local fold
fold = function(op, ...)
  local n = select("#", ...)
  local r = to_u32((...))
  for i = 2, n do
    r = op(r, to_u32((select(i, ...))))
  end
  return to_s32(r)
end
local bit = {
  band = function(...)
    return fold(and2, ...)
  end,
  bor = function(...)
    return fold(or2, ...)
  end,
  bxor = function(...)
    return fold(xor2, ...)
  end,
  bnot = function(a)
    return to_s32(MASK32 - to_u32(a))
  end,
  lshift = function(a, n)
    n = n % 32
    local u = to_u32(a)
    if n == 0 then
      return to_s32(u)
    end
    return to_s32((u % pow2(32 - n)) * pow2(n))
  end,
  rshift = function(a, n)
    n = n % 32
    local u = to_u32(a)
    if n == 0 then
      return to_s32(u)
    end
    return to_s32(math.floor(u / pow2(n)))
  end,
  arshift = function(a, n)
    n = n % 32
    local s = to_s32(to_u32(a))
    if n == 0 then
      return s
    end
    return to_s32(math.floor(s / pow2(n)))
  end
}
return bit
