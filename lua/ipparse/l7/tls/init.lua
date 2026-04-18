local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local bidirectional
bidirectional = require("ipparse.fun").bidirectional
local HKDF
HKDF = require("crypto.hkdf").HKDF
local pack
pack = function(self)
  return sp(">B BB H", self.type, self.ver, self.subver, self.len)
end
local _mt = {
  __tostring = pack
}
local parse
parse = function(self, off)
  if off == nil then
    off = 1
  end
  local _type, ver, subver, len, _off = su(">B BB H", self, off)
  return setmetatable({
    type = _type,
    data_off = _off,
    ver = ver,
    subver = subver,
    len = len
  }, _mt), _off
end
local hkdf_tls13_expand_label
hkdf_tls13_expand_label = function(prk, label, context, length)
  local hkdf = HKDF.new("sha256")
  local hkdf_label_info = pack(">Hs1s1", length, "tls13 " .. label, context)
  return hkdf:expand(prk, hkdf_label_info, length)
end
local record_types = bidirectional({
  [0x14] = "change_cipher_spec",
  [0x15] = "alert",
  [0x16] = "handshake",
  [0x17] = "application_data",
  [0x18] = "heartbeat"
})
return {
  parse = parse,
  pack = pack,
  record_types = record_types
}
