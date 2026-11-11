local need_bytes
need_bytes = require("ipparse").need_bytes
local sp, su, sub, lower
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su, sub, lower = _obj_0.pack, _obj_0.unpack, _obj_0.sub, _obj_0.lower
end
local bidirectional
bidirectional = require("ipparse.fun.tables").bidirectional
local band, bor, bnot, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.rshift
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
local flag_masks = { }
local _list_0 = {
  "FIN",
  "SYN",
  "RST",
  "PSH",
  "ACK",
  "URG"
}
for _index_0 = 1, #_list_0 do
  local name = _list_0[_index_0]
  local mask = flags[name]
  flag_masks[name] = mask
  flag_masks[lower(name)] = mask
end
local pack
pack = function(self)
  return sp(">H H I4 I4 B B H H H", self.spt, self.dpt, self.seq_n, self.ack_n, self.header_len, self.flags, self.window, self.checksum, self.urg_ptr) .. self.options .. tostring(self.data or '')
end
local _mt = {
  __tostring = pack,
  __index = function(self, k)
    do
      local mask = flag_masks[k]
      if mask then
        return band(self.flags, mask) ~= 0
      end
    end
  end,
  __newindex = function(self, k, v)
    do
      local mask = flag_masks[k]
      if mask then
        if v then
          self.flags = bor(self.flags, mask)
        else
          self.flags = band(self.flags, bnot(mask))
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
  local spt, dpt, seq_n, ack_n, header_len, _flags, window, checksum, urg_ptr, _off = su(">H H I4 I4 B B H H H", self, off)
  local data_off = off + rshift(band(header_len, 0xf0), 2)
  if data_off - off < 20 then
    return nil, off
  end
  if not (need_bytes(self, off, data_off - off)) then
    return nil, off
  end
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
  self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = nil, nil, nil, nil, nil, nil
  return setmetatable(self, _mt)
end
return {
  flags = flags,
  parse = parse,
  new = new,
  pack = pack
}
