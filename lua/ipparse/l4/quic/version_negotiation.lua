local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local version = 0
local pack
pack = function(self)
  local parts = { }
  local _list_0 = self.supported_versions
  for _index_0 = 1, #_list_0 do
    local v = _list_0[_index_0]
    parts[#parts + 1] = sp(">I4", v)
  end
  return table.concat(parts)
end
local _mt = {
  __tostring = pack
}
local parse_payload
parse_payload = function(self, off)
  if off == nil then
    off = 1
  end
  local supported_versions = { }
  while off + 3 <= #self do
    local v, _off = su(">I4", self, off)
    supported_versions[#supported_versions + 1] = v
    off = _off
  end
  return setmetatable({
    supported_versions = supported_versions
  }, _mt), off
end
return {
  version = version,
  pack = pack,
  parse_payload = parse_payload
}
