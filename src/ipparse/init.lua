do
  local path = (...):match("(.*)%.[^%.]-")
  if path then
    path = package.path:match("^[^%?]+") .. path
    package.path = package.path .. (";" .. path .. "/?.lua;" .. path .. "/?/init.lua")
  end
end
local su, char, format, gsub, rep, sub
do
  local _obj_0 = string
  su, char, format, gsub, rep, sub = _obj_0.unpack, _obj_0.char, _obj_0.format, _obj_0.gsub, _obj_0.rep, _obj_0.sub
end
local concat
concat = table.concat
local opairs
opairs = require("ipparse.fun").opairs
local dump
dump = function(self)
  return concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    for k, v in opairs(self) do
      _accum_0[_len_0] = tostring(k) .. ": " .. tostring(v)
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)(), ", ")
end
local filterascii
filterascii = function(self)
  return gsub(self, ".", function(self)
    return " " <= self and self <= "~" and self or "."
  end)
end
local bin2hex
bin2hex = function(self)
  return format(rep("%.2x", #self), su(rep("B", #self), self))
end
local lbin2hex
lbin2hex = function(self)
  return concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    for i = 0, #self - 128, 128 do
      _accum_0[_len_0] = bin2hex(sub(self, i + 1, i + 128))
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)())
end
local hex2bin
hex2bin = function(self)
  return gsub(self, "%x%x", function(self)
    return char(tonumber(self, 16))
  end)
end
local hexdump
hexdump = function(self, off, len, cols, f)
  if off == nil then
    off = 1
  end
  if len == nil then
    len = 8
  end
  if cols == nil then
    cols = 2
  end
  if f == nil then
    f = "%.2x"
  end
  local res = { }
  for i = off, #self, len * cols do
    local row = sub(self, i, i + len * cols - 1)
    local hex, ascii = { }, { }
    for j = 1, #row, len do
      local part = sub(row, j, j + len - 1)
      hex[#hex + 1] = format(rep(f, #part), su(rep("B", #part), part))
      ascii[#ascii + 1] = filterascii(part)
    end
    res[#res + 1] = format("%04x: %s %s", i - 1, concat(hex, " "), concat(ascii, rep(" ", len - #ascii[#ascii])))
  end
  return concat(res, "\n")
end
return {
  bin2hex = bin2hex,
  lbin2hex = lbin2hex,
  dump = dump,
  filterascii = filterascii,
  hex2bin = hex2bin,
  hexdump = hexdump
}
