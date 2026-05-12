local format, sub, upper, sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  format, sub, upper, sp, su = _obj_0.format, _obj_0.sub, _obj_0.upper, _obj_0.pack, _obj_0.unpack
end
local checksum
checksum = require("ipparse.l3.lib").checksum
local bidirectional
bidirectional = require("ipparse.fun").bidirectional
local band, bor, bnot, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, lshift, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.lshift, _obj_0.rshift
end
local need_bytes
need_bytes = require("ipparse").need_bytes
local flags = {
  DF = 0x4000,
  MF = 0x2000
}
flags = bidirectional(flags)
local pack
pack = function(self)
  local data = self.data or ""
  if type(data) == "table" then
    data.checksum = 0
    local d = tostring(data)
    data.checksum = checksum(sp(">c4c4 x B s2", self.src, self.dst, self.protocol, d))
    data = tostring(data)
  end
  local header_len = 20 + #(self.options or "")
  self.total_len = header_len + #data
  self.ihl = rshift(header_len, 2)
  if self.version then
    self.v_ihl = bor(lshift(self.version, 4), self.ihl)
  end
  self.checksum = checksum(sp(">BBHHHBBH c4c4", self.v_ihl, self.tos, self.total_len, self.id, self.ff, self.ttl, self.protocol, 0, self.src, self.dst) .. self.options)
  return sp(">BBHHHBBH c4c4", self.v_ihl, self.tos, self.total_len, self.id, self.ff, self.ttl, self.protocol, self.checksum, self.src, self.dst) .. self.options .. data
end
local _mt = {
  __tostring = pack,
  __index = function(self, k)
    do
      local flag = type(k) == "string" and flags[upper(k)]
      if flag then
        return band(self.ff, flag) ~= 0
      end
    end
  end,
  __newindex = function(self, k, v)
    do
      local flag = type(k) == "string" and flags[upper(k)]
      if flag then
        if v then
          self.ff = bor(self.ff, flag)
        else
          self.ff = band(self.ff, bnot(flag))
        end
        return 
      end
    end
    return rawset(self, k, v)
  end
}
local parse
parse = function(self, off)
  if off == nil then
    off = 1
  end
  if not (need_bytes(self, off, 20)) then
    return nil, off
  end
  local v_ihl, tos, total_len, id, ff, ttl, protocol, cksum, src, dst, _off = su(">BBHHHBBH c4c4", self, off)
  local version, ihl = rshift(v_ihl, 4), band(v_ihl, 0x0f)
  local payload_off = lshift(ihl, 2)
  local data_off = off + payload_off
  if not (need_bytes(self, off, data_off - off)) then
    return nil, off
  end
  local options = sub(self, _off, data_off - 1)
  return setmetatable({
    version = version,
    ihl = ihl,
    v_ihl = v_ihl,
    off = off,
    payload_off = payload_off,
    data_off = data_off,
    tos = tos,
    total_len = total_len,
    id = id,
    ff = ff,
    ttl = ttl,
    protocol = protocol,
    checksum = cksum,
    src = src,
    dst = dst,
    options = options
  }, _mt), data_off
end
local new
new = function(self)
  self.version = self.version or 4
  assert(self.version == 4, "IPv4 only (got version " .. tostring(self.version) .. ")")
  self.v_ihl = self.v_ihl or bor(lshift(self.version, 4), self.ihl or 0)
  self.ff = self.ff or bor((self.DF and flags.DF or 0), (self.MF and flags.MF or 0), self.frag_offset or 0)
  self.tos = self.tos or 0
  self.id = self.id or 0
  self.ttl = self.ttl or 64
  return setmetatable(self, _mt)
end
local ip42s
ip42s = function(self)
  return format("%d.%d.%d.%d", su("BBBB", self))
end
local s2ip4
s2ip4 = function(self)
  return sp("BBBB", self:match("(%d+)%.(%d+)%.(%d+)%.(%d+)"))
end
local net42s
net42s = function(self)
  local m, a, b, c, d = su("BBBBB", self)
  return format("%d.%d.%d.%d/%d", a, b, c, d, m)
end
local s2net4
s2net4 = function(self)
  local b1, b2, b3, b4, mask = self:match("(%d+)%.(%d+)%.(%d+)%.(%d+)/?(%d*)")
  return sp("B BBBB", (tonumber(mask) or 32), tonumber(b1), tonumber(b2), tonumber(b3), tonumber(b4))
end
return {
  parse = parse,
  new = new,
  pack = pack,
  ip42s = ip42s,
  s2ip4 = s2ip4,
  net42s = net42s,
  s2net4 = s2net4
}
