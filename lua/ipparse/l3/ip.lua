local bidirectional
bidirectional = require("ipparse.fun").bidirectional
local IP6, IP4
do
  local _obj_0 = require("ipparse.l2.ethernet").proto
  IP6, IP4 = _obj_0.IP6, _obj_0.IP4
end
local ip6, ip6_new, ip6_pack, ip62s, s2ip6, net62s, s2net6
do
  local _obj_0 = require("ipparse.l3.ip6")
  ip6, ip6_new, ip6_pack, ip62s, s2ip6, net62s, s2net6 = _obj_0.parse, _obj_0.new, _obj_0.pack, _obj_0.ip62s, _obj_0.s2ip6, _obj_0.net62s, _obj_0.s2net6
end
local ip4, ip4_new, ip4_pack, ip42s, s2ip4, net42s, s2net4
do
  local _obj_0 = require("ipparse.l3.ip4")
  ip4, ip4_new, ip4_pack, ip42s, s2ip4, net42s, s2net4 = _obj_0.parse, _obj_0.new, _obj_0.pack, _obj_0.ip42s, _obj_0.s2ip4, _obj_0.net42s, _obj_0.s2net4
end
local sub, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sub, su = _obj_0.sub, _obj_0.unpack
end
local band, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, lshift, rshift = _obj_0.band, _obj_0.lshift, _obj_0.rshift
end
local get_version
get_version = function(self, off)
  return rshift(su("B", self, off), 4)
end
local pack
pack = function(self)
  return self.version == 6 and ip6_pack(self) or ip4_pack(self)
end
local parse
parse = function(self, off)
  local res, _off
  local v = get_version(self, off)
  local _exp_0 = v
  if 6 == _exp_0 then
    res, _off = ip6(self, off)
  elseif 4 == _exp_0 then
    res, _off = ip4(self, off)
  else
    return nil, "Unknown IP version " .. tostring(v) .. " at offset " .. tostring(off)
  end
  if not res then
    return nil, "Failed to parse IP header"
  end
  local header_len = res.data_off - res.off
  res.total_len = res.total_len or (res.payload_len + header_len)
  res.payload_len = res.payload_len or (res.total_len - header_len)
  res.next_header = res.next_header or res.protocol
  res.protocol = res.protocol or res.next_header
  return res, _off
end
local new
new = function(self)
  return self.version == 6 and ip6_new(self) or ip4_new(self)
end
local ip2s
ip2s = function(self)
  return (#self == 16 and ip62s or #self == 4 and ip42s)(self)
end
local s2ip
s2ip = function(self)
  return self:match(":") and s2ip6(self) or s2ip4(self)
end
local net2s
net2s = function(self)
  return (#self == 17 and net62s or #self == 5 and net42s)(self)
end
local s2net
s2net = function(self)
  return (self:match(":") and s2net6 or self:match("%.") and s2net4)(self)
end
local contains_ip
contains_ip = function(self, i, nmask)
  if not nmask then
    if #self ~= #i + 1 then
      return false
    end
    nmask = su("B", self)
    if nmask == lshift(#i, 3) then
      return sub(self, 2) == i
    end
  end
  local fmt, shft = "c" .. tostring(rshift(nmask, 3)) .. "B", 8 - band(nmask, 0x7)
  local nbytes, nbits = su(fmt, self, 2)
  local sbytes, sbits = su(fmt, i)
  if nbytes == sbytes and rshift(nbits, shft) == rshift(sbits, shft) then
    return true
  end
  return false
end
local contains_subnet
contains_subnet = function(self, subnet)
  if #self ~= #subnet then
    return false
  end
  local nmask, smask = su("B", self), su("B", subnet)
  if nmask > smask then
    return false
  end
  if nmask == smask then
    return self == subnet
  end
  return contains_ip(self, sub(subnet, 2), nmask)
end
local proto = bidirectional({
  ["ICMP"] = 0x01,
  ["TCP"] = 0x06,
  ["UDP"] = 0x11,
  ["GRE"] = 0x2F,
  ["ESP"] = 0x32,
  ["ICMPv6"] = 0x3A,
  ["OSPF"] = 0x59
})
return {
  get_version = get_version,
  parse = parse,
  new = new,
  pack = pack,
  proto = proto,
  ip2s = ip2s,
  s2ip = s2ip,
  net2s = net2s,
  s2net = s2net,
  contains_subnet = contains_subnet,
  contains_ip = contains_ip
}
