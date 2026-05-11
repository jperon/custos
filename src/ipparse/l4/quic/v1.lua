local upper
upper = string.upper
local bidirectional, zero_indexed
do
  local _obj_0 = require("ipparse.fun")
  bidirectional, zero_indexed = _obj_0.bidirectional, _obj_0.zero_indexed
end
local band, bor, bnot, lshift, rshift
do
  local _obj_0 = require("ipparse.lib.bit_compat")
  band, bor, bnot, lshift, rshift = _obj_0.band, _obj_0.bor, _obj_0.bnot, _obj_0.lshift, _obj_0.rshift
end
local version = 0x01
local initial_salt = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"
local byte1_long = bidirectional({
  HEADER_FORM = 0x80,
  FIXED_BIT = 0x40,
  PKT_TYPE = 0x30,
  TYPE_BITS = 0x0f
})
local byte1_short = bidirectional({
  HEADER_FORM = 0x80,
  FIXED_BIT = 0x40,
  SPIN_BIT = 0x20,
  RESERVED_BITS = 0x18,
  KEY_PHASE = 0x04,
  PKT_NUM_LENGTH = 0x03
})
local packet_types = zero_indexed({
  "initial",
  "zero_rtt",
  "handshake",
  "retry"
})
for i = 0, #packet_types - 1 do
  packet_types[lshift(i, 4)] = packet_types[i]
end
packet_types = bidirectional(packet_types)
local generate_mt
generate_mt = function(byte1)
  return {
    __index = function(self, k)
      if type(k) == "string" then
        do
          local mask = byte1[upper(k)]
          if mask then
            return band(self.byte1, mask)
          end
        end
      end
    end,
    __newindex = function(self, k, v)
      if type(k) == "string" then
        do
          local mask = byte1[upper(k)]
          if mask then
            if v == true then
              v = mask
            end
            self.byte1 = bor(band(self.byte1, bnot(mask)), v or 0)
          end
        end
      end
    end
  }
end
return {
  version = version,
  initial_salt = initial_salt,
  long_mt = generate_mt(byte1_long),
  short_mt = generate_mt(byte1_short),
  byte1_long = byte1_long,
  byte1_short = byte1_short,
  packet_types = packet_types
}
