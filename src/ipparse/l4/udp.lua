local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local pack
pack = function(self)
  self.len = 8 + (self.data and #tostring(self.data) or 0)
  return sp(">H H H H", self.spt, self.dpt, self.len, self.checksum) .. tostring(self.data or '')
end
local _mt = {
  __tostring = pack
}
local parse
parse = function(self, off)
  if off == nil then
    off = 1
  end
  local spt, dpt, len, checksum, data_off = su(">H H H H", self, off)
  return setmetatable({
    spt = spt,
    dpt = dpt,
    len = len,
    checksum = checksum,
    off = off,
    data_off = data_off
  }, _mt), data_off
end
local new
new = function(self)
  return setmetatable(self, _mt)
end
return {
  parse = parse,
  new = new,
  pack = pack
}
