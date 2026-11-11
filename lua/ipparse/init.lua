do
  local path = (...):match("(.*)%.[^%.]-")
  if path then
    path = package.path:match("^[^%?]+") .. path
    package.path = package.path .. (";" .. path .. "/?.lua;" .. path .. "/?/init.lua")
  end
end
local byte, char, format, gsub, rep, sub
do
  local _obj_0 = string
  byte, char, format, gsub, rep, sub = _obj_0.byte, _obj_0.char, _obj_0.format, _obj_0.gsub, _obj_0.rep, _obj_0.sub
end
local su
su = require("ipparse.lib.pack_compat").unpack
local concat
concat = table.concat
local opairs
opairs = require("ipparse.fun.tables").opairs
if leak_debug ~= nil then
  require("ipparse.fun.protected").leak_debug = leak_debug
end
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
filterascii = function(s)
  return gsub(s, ".", function(self)
    return " " <= self and self <= "~" and self or "."
  end)
end
local need_bytes
need_bytes = function(self, off, len)
  if off < 1 or len < 0 then
    return false
  end
  return (off + len - 1) <= #self
end
local bin2hex
bin2hex = function(s)
  return (gsub(s, ".", function(c)
    return format("%.2x", byte(c))
  end))
end
local lbin2hex = bin2hex
local hex2bin
hex2bin = function(self)
  return (gsub(self, "%x%x", function(self)
    return char(tonumber(self, 16))
  end))
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
  local width = cols * len * #format(f, 0) + cols - 1
  local res = { }
  for i = off, #self, len * cols do
    local row = sub(self, i, i + len * cols - 1)
    local hex, ascii = { }, { }
    for j = 1, #row, len do
      local part = sub(row, j, j + len - 1)
      hex[#hex + 1] = format(rep(f, #part), su(rep("B", #part), part))
      ascii[#ascii + 1] = filterascii(part)
    end
    local hexstr = concat(hex, " ")
    res[#res + 1] = format("%04x: %s%s %s", i - 1, hexstr, rep(" ", width - #hexstr), concat(ascii))
  end
  return concat(res, "\n")
end
return {
  bin2hex = bin2hex,
  lbin2hex = lbin2hex,
  dump = dump,
  filterascii = filterascii,
  hex2bin = hex2bin,
  hexdump = hexdump,
  leak_debug = leak_debug,
  need_bytes = need_bytes
}
