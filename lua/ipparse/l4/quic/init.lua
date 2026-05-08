local sp, su, byte
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su, byte = _obj_0.pack, _obj_0.unpack, _obj_0.byte
end
local bidirectional
bidirectional = require("ipparse.fun").bidirectional
local band
band = require("ipparse.lib.bit_compat").band
local parse_varint
parse_varint = require("ipparse.l4.quic.frames").parse_varint
local versions
do
  local _tbl_0 = { }
  local _list_0
  do
    local _accum_0 = { }
    local _len_0 = 1
    local _list_1 = {
      "version_negotiation",
      "v1"
    }
    for _index_0 = 1, #_list_1 do
      local v = _list_1[_index_0]
      _accum_0[_len_0] = require("ipparse.l4.quic." .. tostring(v))
      _len_0 = _len_0 + 1
    end
    _list_0 = _accum_0
  end
  for _index_0 = 1, #_list_0 do
    local v = _list_0[_index_0]
    _tbl_0[v.version] = v
  end
  versions = _tbl_0
end
local flags = bidirectional({
  HEADER_FORM = 0x80
})
local HEADER_FORM
HEADER_FORM = flags.HEADER_FORM
local pack
pack = function(self)
  if self.long_header then
    return sp(">BH s1 s1", self.byte1, self.version, self.dst_connection_id, self.src_connection_id) .. (self.data and tostring(self.data) or "")
  else
    return sp(">B", self.byte1) .. self.dst_connection_id
  end
end
local _mt = {
  __tostring = pack
}
for _index_0 = 1, #versions do
  local _des_0 = versions[_index_0]
  local long_mt, short_mt
  long_mt, short_mt = _des_0.long_mt, _des_0.short_mt
  for k, v in pairs(_mt) do
    local _update_0 = k
    long_mt[_update_0] = long_mt[_update_0] or v
  end
  for k, v in pairs(_mt) do
    local _update_0 = k
    short_mt[_update_0] = short_mt[_update_0] or v
  end
end
local parse_long_header
parse_long_header = function(self, off, byte1)
  local version, dst_connection_id, src_connection_id, _off = su(">I4 s1 s1", self, off)
  local mt
  local pkt_type, token, pkt_length
  do
    local v = versions[version]
    if v then
      mt = v.long_mt
      pkt_type = band(byte1, 0x30)
    end
  end
  mt = mt or _mt
  if pkt_type == 0x00 then
    local token_len
    token_len, _off = parse_varint(self, _off)
    token = self:sub(_off, _off + token_len - 1)
    _off = _off + token_len
  end
  if pkt_type ~= 0x30 then
    pkt_length, _off = parse_varint(self, _off)
  end
  return setmetatable({
    byte1 = byte1,
    version = version,
    dst_connection_id = dst_connection_id,
    src_connection_id = src_connection_id,
    token = token,
    pkt_length = pkt_length,
    pkt_type = pkt_type,
    pn_off = _off,
    data_off = _off,
    payload_off = _off,
    long_header = true
  }, mt), _off
end
local parse_short_header
parse_short_header = function(self, off, byte1, dst_id, src_connection_id, version)
  if dst_id == nil then
    dst_id = nil
  end
  if src_connection_id == nil then
    src_connection_id = nil
  end
  if version == nil then
    version = nil
  end
  local mt, dst_connection_id, _off
  if dst_id then
    dst_connection_id, _off = su(">c" .. tostring(#dst_id), self, off)
  end
  do
    local v = versions[version]
    if v then
      mt = v.short_mt
    end
  end
  mt = mt or _mt
  return setmetatable({
    byte1 = byte1,
    version = version,
    dst_connection_id = dst_connection_id,
    src_connection_id = src_connection_id,
    data_off = _off,
    payload_off = _off
  }, mt), _off
end
local parse
parse = function(self, off, ...)
  if off == nil then
    off = 1
  end
  local byte1 = byte(self, off)
  if band(byte1, HEADER_FORM) == 0 then
    return parse_short_header(self, off + 1, byte1, ...)
  else
    return parse_long_header(self, off + 1, byte1)
  end
end
return {
  versions = versions,
  pack = pack,
  parse = parse
}
