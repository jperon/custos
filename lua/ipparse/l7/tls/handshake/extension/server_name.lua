local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local concat
concat = table.concat
local bidirectional, zero_indexed
do
  local _obj_0 = require("ipparse.fun")
  bidirectional, zero_indexed = _obj_0.bidirectional, _obj_0.zero_indexed
end
local pack_entry
pack_entry = function(self)
  return sp(">B s2", self.type, self.name)
end
local _mt_entry = {
  __tostring = pack_entry
}
local parse_entry
parse_entry = function(self, off)
  if off == nil then
    off = 1
  end
  local name_type, name, _off = su(">B s2", self, off)
  return setmetatable({
    type = name_type,
    name = name
  }, _mt_entry), _off
end
local pack
pack = function(self)
  return sp(">s2", self.names and concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    local _list_0 = self.names
    for _index_0 = 1, #_list_0 do
      local entry = _list_0[_index_0]
      _accum_0[_len_0] = pack_entry(entry)
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)()) or "")
end
local _mt = {
  __tostring = pack
}
local parse
parse = function(self, off)
  if off == nil then
    off = 1
  end
  local len, _off = su(">H", self, off)
  local end_offset = _off + len
  local names = { }
  local ok = true
  local err = nil
  while _off < end_offset do
    local entry
    ok, entry, _off = pcall(parse_entry, self, _off)
    if not ok then
      err = tostring(entry)
      break
    end
    names[#names + 1] = entry
  end
  return setmetatable({
    names = names,
    name = (names[1] and names[1].name),
    incomplete = not ok,
    err = err
  }, _mt), _off
end
local name_types = bidirectional(zero_indexed({
  "HOST_NAME"
}))
return {
  parse = parse,
  pack = pack,
  parse_entry = parse_entry,
  pack_entry = pack_entry,
  name_types = name_types
}
