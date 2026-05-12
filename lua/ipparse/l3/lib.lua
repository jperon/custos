local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local band, bor, bnot, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, lshift, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.lshift, _obj_0.rshift
end
local checksum
checksum = function(self)
  local cksm = 0
  if band(#self, 1) == 1 then
    self = self .. "\0"
  end
  for i = 1, #self, 2 do
    cksm = cksm + su(">H", self, i)
  end
  while true do
    local carry = rshift(cksm, 16)
    if carry == 0 then
      break
    end
    cksm = band(cksm, 0xFFFF) + carry
  end
  return band(bnot(cksm), 0xFFFF)
end
local checksum6
checksum6 = function(src, dst, next_header, payload)
  return checksum(sp(">c16c16 I4 xxx B c" .. tostring(#payload), src, dst, #payload, next_header, payload))
end
return {
  checksum = checksum,
  checksum6 = checksum6
}
