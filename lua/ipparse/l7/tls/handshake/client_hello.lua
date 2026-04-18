local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local pack
pack = function(self)
  return sp(">H c32 s1 s2 s1 s2", self.version, self.client_random, self.session_id, self.ciphers, self.compressions, self.extensions)
end
local _mt = {
  __tostring = pack
}
local parse
parse = function(self, off)
  if off == nil then
    off = 1
  end
  local version, client_random, session_id, ciphers, compressions, extensions, _off = su(">H c32 s1 s2 s1 s2", self, off)
  return setmetatable({
    version = version,
    client_random = client_random,
    session_id = session_id,
    ciphers = ciphers,
    compressions = compressions,
    extensions = extensions
  }, _mt), _off
end
return {
  parse = parse,
  pack = pack
}
