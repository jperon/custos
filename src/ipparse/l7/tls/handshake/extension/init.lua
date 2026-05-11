local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local pack
pack = function(self)
  return sp(">H s2", self.type, self.data)
end
local _mt = {
  __tostring = pack
}
local parse
parse = function(self, off)
  if off == nil then
    off = 1
  end
  local _type, data, _off = su(">H s2", self, off)
  return setmetatable({
    type = _type,
    data = data
  }, _mt), _off
end
return {
  parse = parse,
  pack = pack
}
