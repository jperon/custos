local format, sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  format, sp, su = _obj_0.format, _obj_0.pack, _obj_0.unpack
end
local insert, remove
do
  local _obj_0 = table
  insert, remove = _obj_0.insert, _obj_0.remove
end
local unpack = unpack or table.unpack
local toarray
toarray = require("ipparse.fun").toarray
local checksum
checksum = require("ipparse.l3.lib").checksum
local band, bor, bnot, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, lshift, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.lshift, _obj_0.rshift
end
local s2ip6
local pack
pack = function(self)
  local data = self.data or ""
  if type(data) == "table" then
    data.checksum = 0
    local d = tostring(data)
    data.checksum = checksum(sp(">c16c16 I4 xxx B c" .. tostring(#d), self.src, self.dst, #d, self.next_header, d))
    data = tostring(data)
  end
  self.payload_len = #data
  self.vtf = self.vtf or bor(lshift(self.version, 28), lshift(self.traffic_class or 0, 20), self.flow_label or 0)
  return sp(">I4 I2 I1 I1 c16 c16", self.vtf, self.payload_len, self.next_header, self.hop_limit, self.src, self.dst) .. tostring(self.data or '')
end
local _mt = {
  __tostring = pack
}
local parse
parse = function(self, off)
  if off == nil then
    off = 1
  end
  local vtf, payload_len, next_header, hop_limit, src, dst, data_off = su(">I4 I2 I1 I1 c16 c16", self, off)
  return setmetatable({
    vtf = vtf,
    version = rshift(vtf, 28),
    traffic_class = band(rshift(vtf, 20), 0xff),
    flow_label = band(vtf, 0xfffff),
    payload_len = payload_len,
    next_header = next_header,
    hop_limit = hop_limit,
    src = src,
    dst = dst,
    off = off,
    data_off = data_off
  }, _mt), data_off
end
local new
new = function(self)
  self.version = self.version or 6
  assert(self.version == 6, "IPv6 only")
  self.hop_limit = self.hop_limit or 64
  self.payload_len = self.payload_len or 0
  self.next_header = self.next_header or 0
  self.traffic_class = self.traffic_class or 0
  self.flow_label = self.flow_label or 0
  self.vtf = self.vtf or bor(lshift(self.version, 28), lshift(self.traffic_class or 0, 20), self.flow_label or 0)
  return setmetatable(self, _mt)
end
local parse_ip6
parse_ip6 = function(self)
  local address = toarray(self:gmatch("([^:]*):?"))
  local zeros = 9 - #address
  for i = 1, 8 do
    local part = address[i]
    if part == "" and zeros then
      for _ = 1, zeros do
        insert(address, i, 0)
        i = i + 1
      end
      zeros = 1
      remove(address, i)
    else
      address[i] = type(part) == "string" and tonumber(part, 16) or part
    end
  end
  return address
end
local ip62s
ip62s = function(self)
  return format("%x:%x:%x:%x:%x:%x:%x:%x", su(">HHHH HHHH", self))
end
s2ip6 = function(self)
  return sp(">HHHH HHHH", unpack(parse_ip6(self)))
end
local net62s
net62s = function(self)
  local m, a, b, c, d, e, f, g, h = su(">B HHHH HHHH", self)
  return format("%x:%x:%x:%x:%x:%x:%x:%x/%d", a, b, c, d, e, f, g, h, m)
end
local s2net6
s2net6 = function(self)
  local mask
  self, mask = self:match("([^/]*)/?([^/]*)$")
  return sp(">B HHHH HHHH", (tonumber(mask or 128)), unpack(parse_ip6(self)))
end
return {
  parse = parse,
  new = new,
  ip62s = ip62s,
  s2ip6 = s2ip6,
  net62s = net62s,
  s2net6 = s2net6
}
