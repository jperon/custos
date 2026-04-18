local ok, bit = pcall(require, "bit")
if ok then
  return bit
end
ok, bit = pcall(require, "bit32")
if ok then
  return bit
end
ok, bit = pcall(require, "bit53")
return bit
