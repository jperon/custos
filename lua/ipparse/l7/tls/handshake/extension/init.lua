local sp, su, sub
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su, sub = _obj_0.pack, _obj_0.unpack, _obj_0.sub
end
local need_bytes
need_bytes = require("ipparse").need_bytes
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
  if not (need_bytes(self, off, 4)) then
    return nil, off
  end
  local _type, dlen = su(">HH", self, off)
  if not (need_bytes(self, off + 4, dlen)) then
    return nil, off
  end
  local data = sub(self, off + 4, off + 3 + dlen)
  return setmetatable({
    type = _type,
    data = data
  }, _mt), off + 4 + dlen
end
return {
  parse = parse,
  pack = pack
}
