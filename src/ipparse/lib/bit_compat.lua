local pow2
pow2 = function(n)
  local p = 1
  for _ = 1, n do
    p = p * 2
  end
  return p
end
local fallback_lshift
fallback_lshift = function(a, n)
  if n <= 0 then
    return a
  end
  return a * pow2(n)
end
local fallback_rshift
fallback_rshift = function(a, n)
  if n <= 0 then
    return a
  end
  return math.floor((a % 0x100000000) / pow2(n))
end
local normalize
normalize = function(bit)
  bit.lshift = bit.lshift or bit.blshift or fallback_lshift
  bit.rshift = bit.rshift or bit.brshift or fallback_rshift
  bit.arshift = bit.arshift or bit.rshift
  return bit
end
local ok, bit = pcall(require, "bit")
if ok and bit then
  return normalize(bit)
end
ok, bit = pcall(require, "bit32")
if ok and bit then
  return normalize(bit)
end
ok, bit = pcall(require, "ipparse.lib.bit53")
if ok and bit then
  return normalize(bit)
end
return error("no bitwise compatibility backend available")
