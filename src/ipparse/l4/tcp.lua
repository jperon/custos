local sp, su, sub, upper
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su, sub, upper = _obj_0.pack, _obj_0.unpack, _obj_0.sub, _obj_0.upper
end
local bidirectional
bidirectional = require("ipparse.fun").bidirectional
local band, bor, bnot, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, lshift, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.lshift, _obj_0.rshift
end
local flags = bidirectional({
  FIN = 0x01,
  SYN = 0x02,
  RST = 0x04,
  PSH = 0x08,
  ACK = 0x10,
  URG = 0x20
})
local FIN, SYN, RST, PSH, ACK, URG
FIN, SYN, RST, PSH, ACK, URG = flags.FIN, flags.SYN, flags.RST, flags.PSH, flags.ACK, flags.URG
local pack
pack = function(self)
  return sp(">H H I4 I4 B B H H H", self.spt, self.dpt, self.seq_n, self.ack_n, self.header_len, self.flags, self.window, self.checksum, self.urg_ptr) .. self.options .. tostring(self.data or '')
end
local _mt = {
  __tostring = pack,
  __index = function(self, k)
    do
      local flag = type(k) == "string" and upper(k)
      if flag then
        do
          flag = flags[flag]
          if flag then
            return band(self.flags, flag) ~= 0
          end
        end
      end
    end
  end,
  __newindex = function(self, k, v)
    do
      local flag = type(k) == "string" and upper(k)
      if flag then
        do
          flag = flags[flag]
          if flag then
            if v then
              self.flags = bor(self.flags, flag)
            else
              self.flags = band(self.flags, bnot(flag))
            end
            return 
          end
        end
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
  local spt, dpt, seq_n, ack_n, header_len, _flags, window, checksum, urg_ptr, _off = su(">H H I4 I4 B B H H H", self, off)
  local data_off = off + rshift(band(header_len, 0xf0), 2)
  local options = sub(self, _off, data_off - 1)
  return setmetatable({
    spt = spt,
    dpt = dpt,
    seq_n = seq_n,
    ack_n = ack_n,
    off = off,
    header_len = header_len,
    data_off = data_off,
    flags = _flags,
    window = window,
    checksum = checksum,
    urg_ptr = urg_ptr,
    options = options
  }, _mt), data_off
end
local new
new = function(self)
  self.flags = bor((self.flags or 0), (self.urg and URG or 0), (self.ack and ACK or 0), (self.psh and PSH or 0), (self.rst and RST or 0), (self.syn and SYN or 0), (self.fin and FIN or 0))
  return setmetatable(self, _mt)
end
return {
  flags = flags,
  parse = parse,
  new = new,
  pack = pack
}
