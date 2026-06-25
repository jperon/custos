local ffi = require("ffi")
local bit = require("bit")
local STRIP_MSG_SIZE = 10
local FNV_OFFSET = 0xcbf29ce484222325ULL
local FNV_PRIME = 0x100000001b3ULL
local normalize
normalize = function(name)
  if not (name and name ~= "") then
    return ""
  end
  return (tostring(name)):lower():gsub("%.+$", "")
end
local bit_xor_byte
bit_xor_byte = function(h, b)
  local lo = tonumber(h % 256ULL)
  local xored = bit.bxor(lo, b)
  return (h - lo) + xored
end
local name_hash
name_hash = function(name)
  local h = FNV_OFFSET
  local s = normalize(name)
  for i = 1, #s do
    h = bit_xor_byte(h, s:byte(i))
    h = h * FNV_PRIME
  end
  local out = { }
  for shift = 56, 0, -8 do
    out[#out + 1] = string.char(tonumber((h / (2ULL ^ shift)) % 256ULL))
  end
  return table.concat(out)
end
local encode
encode = function(name, rr_code)
  local rr = tonumber(rr_code) or 0
  return name_hash(name) .. string.char(math.floor(rr / 256) % 256, rr % 256)
end
local decode
decode = function(msg)
  if not (msg and #msg >= STRIP_MSG_SIZE) then
    return nil
  end
  local hash8 = msg:sub(1, 8)
  local rr = msg:byte(9) * 256 + msg:byte(10)
  return hash8, rr
end
return {
  normalize = normalize,
  name_hash = name_hash,
  encode = encode,
  decode = decode,
  STRIP_MSG_SIZE = STRIP_MSG_SIZE
}
