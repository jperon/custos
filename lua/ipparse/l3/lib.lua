local sp
sp = require("ipparse.lib.pack_compat").pack
local byte
byte = string.byte
local band, bor, bnot, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, lshift, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.lshift, _obj_0.rshift
end
local checksum
checksum = function(self)
  local len = #self
  local even = len - band(len, 1)
  local cksm = 0
  for i = 1, even, 2 do
    local a, b = byte(self, i, i + 1)
    cksm = cksm + (a * 256 + b)
  end
  if even < len then
    cksm = cksm + (byte(self, len) * 256)
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
  return checksum(sp(">c16c16 I4 xxx B", src, dst, #payload, next_header) .. payload)
end
return {
  checksum = checksum,
  checksum6 = checksum6
}
