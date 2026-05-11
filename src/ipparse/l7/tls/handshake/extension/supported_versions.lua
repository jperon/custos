local sp, su
do
  local _obj_0 = require("ipparse.lib.pack_compat")
  sp, su = _obj_0.pack, _obj_0.unpack
end
local bidirectional
bidirectional = require("ipparse.fun").bidirectional
local concat
concat = table.concat
local versions = bidirectional({
  [0x0300] = "SSL 3.0",
  [0x0301] = "TLS 1.0",
  [0x0302] = "TLS 1.1",
  [0x0303] = "TLS 1.2",
  [0x0304] = "TLS 1.3"
})
local pack_list
pack_list = function(self)
  return sp(">B", #self.versions * 2) .. concat((function()
    local _accum_0 = { }
    local _len_0 = 1
    local _list_0 = self.versions
    for _index_0 = 1, #_list_0 do
      local v = _list_0[_index_0]
      _accum_0[_len_0] = sp(">H", v)
      _len_0 = _len_0 + 1
    end
    return _accum_0
  end)())
end
local pack_selected
pack_selected = function(self)
  return sp(">H", self.selected)
end
local _mt_list = {
  __tostring = pack_list
}
local _mt_selected = {
  __tostring = pack_selected
}
local parse
parse = function(self, off)
  if off == nil then
    off = 1
  end
  if #self - off + 1 == 2 then
    local ver, _off = su(">H", self, off)
    return setmetatable({
      selected = ver
    }, _mt_selected), _off
  else
    local len, _off = su(">B", self, off)
    local list
    do
      local _accum_0 = { }
      local _len_0 = 1
      for i = _off, _off + len - 1, 2 do
        _accum_0[_len_0] = su(">H", self, i)
        _len_0 = _len_0 + 1
      end
      list = _accum_0
    end
    return setmetatable({
      versions = list
    }, _mt_list), _off + len
  end
end
return {
  parse = parse,
  versions = versions
}
