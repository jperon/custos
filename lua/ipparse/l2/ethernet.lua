local bidirectional
bidirectional = require("ipparse.fun").bidirectional
local format, sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  format, sp, su = _obj_0.format, _obj_0.pack, _obj_0.unpack
end
local need_bytes
need_bytes = require("ipparse").need_bytes
local band
band = require("ipparse.lib.bit_compat").band
local unpack = unpack or table.unpack
local ETH_P_8021Q = 0x8100
local pack
pack = function(self)
  if self.vlan and self.vlan ~= 0 then
    return sp("c6 c6 >HHH", self.dst, self.src, ETH_P_8021Q, self.vlan, self.protocol) .. tostring(self.data or '')
  else
    return sp("c6 c6 >H", self.dst, self.src, self.protocol) .. tostring(self.data or '')
  end
end
local _mt = {
  __tostring = pack
}
local parse
parse = function(self, off)
  if off == nil then
    off = 1
  end
  if not (need_bytes(self, off, 14)) then
    return nil, off
  end
  local dst, src, protocol, data_off = su("c6 c6 >H", self, off)
  local vlan = nil
  if protocol == ETH_P_8021Q then
    if not (need_bytes(self, data_off, 4)) then
      return nil, off
    end
    local tci
    tci, protocol, data_off = su(">HH", self, data_off)
    vlan = band(tci, 0xFFF)
  end
  return setmetatable({
    dst = dst,
    src = src,
    protocol = protocol,
    vlan = vlan,
    off = off,
    data_off = data_off
  }, _mt), data_off
end
local new
new = function(self)
  return setmetatable(self, _mt)
end
local mac2s
mac2s = function(self)
  return format("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", su("BBBBBB", self))
end
local s2mac
s2mac = function(self)
  return sp("BBBBBB", unpack((function()
    local _accum_0 = { }
    local _len_0 = 1
    for s in self:gmatch("[^:]+") do
      _accum_0[_len_0] = tonumber(s, 16)
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)()))
end
local proto = {
  IP6 = 0x86DD,
  IP4 = 0x800
}
proto = bidirectional(proto)
return {
  parse = parse,
  new = new,
  pack = pack,
  proto = proto,
  mac2s = mac2s,
  s2mac = s2mac,
  ETH_P_8021Q = ETH_P_8021Q
}
