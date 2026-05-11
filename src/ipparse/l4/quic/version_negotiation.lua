local sp, su, rep
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su, rep = _obj_0.pack, _obj_0.unpack, _obj_0.rep
end
local remove
remove = table.remove
local version = 0
local pack
pack = function(self)
  return sp(rep(">H", #self.supported_versions), self.supported_versions)
end
local _mt = {
  __tostring = pack
}
local parse_payload
parse_payload = function(self, off)
  if off == nil then
    off = 1
  end
  local supported_versions = {
    su(rep(">H", #self / 2), self, off)
  }
  local _off = remove(supported_versions)
  return setmetatable({
    supported_versions = supported_versions
  }, _mt), _off
end
return {
  version = version,
  pack = pack,
  parse_payload = parse_payload
}
