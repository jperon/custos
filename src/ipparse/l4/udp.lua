local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local need_bytes
need_bytes = require("ipparse").need_bytes
local l3_checksum6
l3_checksum6 = require("ipparse.l3.lib").checksum6
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
  if not (need_bytes(self, off, 8)) then
    return nil, off
  end
  local spt, dpt, len, csum, data_off = su(">H H H H", self, off)
  return setmetatable({
    spt = spt,
    dpt = dpt,
    len = len,
    checksum = csum,
    off = off,
    data_off = data_off
  }, _mt), data_off
end
local checksum6
checksum6 = function(src, dst, udp_pkt)
  local csum = l3_checksum6(src, dst, 17, udp_pkt)
  if csum == 0 then
    csum = 0xFFFF
  end
  return csum
end
local new
new = function(self)
  return setmetatable(self, _mt)
end
return {
  parse = parse,
  new = new,
  pack = pack,
  checksum6 = checksum6
}
