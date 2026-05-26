if string.unpack then
  return string
end
local tunpack = unpack or table.unpack
local ffi = require("ffi")
ffi.cdef([[  void *memcpy(void *dest, const void *src, size_t n);
  void *memset(void *s, int c, size_t n);
]])
local NATIVE_LE
do
  local probe = ffi.new("uint16_t[1]", 0x0102)
  local pb = ffi.cast("uint8_t *", probe)
  NATIVE_LE = pb[0] == 0x02
end
local read_uint
read_uint = function(s, offset, size, le)
  if size == 1 then
    return string.byte(s, offset + 1)
  end
  if size == 2 then
    local a, b = string.byte(s, offset + 1, offset + 2)
    return le and (b * 256 + a) or (a * 256 + b)
  end
  if size == 4 then
    local a, b, c, d = string.byte(s, offset + 1, offset + 4)
    return le and (d * 16777216 + c * 65536 + b * 256 + a) or (a * 16777216 + b * 65536 + c * 256 + d)
  end
  local val = ffi.cast("uint64_t", 0)
  if le then
    for i = size - 1, 0, -1 do
      val = val * 256 + string.byte(s, offset + i + 1)
    end
  else
    for i = 0, size - 1 do
      val = val * 256 + string.byte(s, offset + i + 1)
    end
  end
  return val
end
local write_uint
write_uint = function(buf, offset, val, size, le)
  local v = ffi.cast("uint64_t", val)
  if le then
    for i = 0, size - 1 do
      buf[offset + i] = tonumber(v % 256)
      v = v / 256
    end
  else
    for i = size - 1, 0, -1 do
      buf[offset + i] = tonumber(v % 256)
      v = v / 256
    end
  end
end
local to_signed
to_signed = function(val, size)
  local uval = tonumber(ffi.cast("uint64_t", val))
  local bits = size * 8
  local limit = 2 ^ (bits - 1)
  if uval >= limit then
    return uval - 2 ^ bits
  else
    return uval
  end
end
local parse_format
parse_format = function(fmt)
  local i = 1
  local le = NATIVE_LE
  local align = true
  return function()
    while i <= #fmt do
      local _continue_0 = false
      repeat
        do
          local c = fmt:sub(i, i)
          i = i + 1
          if c == ">" then
            le = false
            align = false
            _continue_0 = true
            break
          end
          if c == "<" then
            le = true
            align = false
            _continue_0 = true
            break
          end
          if c == "=" then
            le = NATIVE_LE
            align = false
            _continue_0 = true
            break
          end
          if c == "!" then
            if i <= #fmt and fmt:sub(i, i):match("%d") then
              i = i + 1
            end
            align = true
            _continue_0 = true
            break
          end
          if c == " " then
            _continue_0 = true
            break
          end
          local count = nil
          if i <= #fmt then
            local nc = fmt:sub(i, i)
            if nc:match("%d") then
              count = tonumber(nc)
              i = i + 1
              while i <= #fmt and fmt:sub(i, i):match("%d") do
                count = count * 10 + tonumber(fmt:sub(i, i))
                i = i + 1
              end
            end
          end
          return c, count, le, align
        end
        _continue_0 = true
      until true
      if not _continue_0 then
        break
      end
    end
    return nil
  end
end
local element_size
element_size = function(opt, count)
  local _exp_0 = opt
  if "b" == _exp_0 or "B" == _exp_0 then
    return 1
  elseif "h" == _exp_0 or "H" == _exp_0 then
    return 2
  elseif "i" == _exp_0 or "I" == _exp_0 then
    return count or 4
  elseif "l" == _exp_0 or "L" == _exp_0 then
    return 8
  elseif "j" == _exp_0 or "J" == _exp_0 then
    return 8
  elseif "T" == _exp_0 then
    return 8
  elseif "f" == _exp_0 then
    return 4
  elseif "d" == _exp_0 or "n" == _exp_0 then
    return 8
  elseif "e" == _exp_0 then
    return 2
  elseif "c" == _exp_0 then
    return count or 1
  elseif "s" == _exp_0 then
    return nil
  elseif "z" == _exp_0 then
    return nil
  elseif "x" == _exp_0 then
    return 1
  elseif "X" == _exp_0 then
    return 0
  else
    return error("option de format inconnue : '" .. tostring(opt) .. "'")
  end
end
local packsize
packsize = function(fmt)
  local total = 0
  local iter = parse_format(fmt)
  local opt, count, le, align = iter()
  while opt ~= nil do
    local sz = element_size(opt, count)
    if sz == nil then
      error("string.packsize : format '" .. tostring(opt) .. "' a une taille variable")
    end
    total = total + sz
    opt, count, le, align = iter()
  end
  return total
end
local _fmt_cache = { }
local parse_format_to_ops
parse_format_to_ops = function(fmt)
  local ops = { }
  local iter = parse_format(fmt)
  local opt, count, le, align = iter()
  while opt ~= nil do
    ops[#ops + 1] = {
      opt,
      count,
      le
    }
    opt, count, le, align = iter()
  end
  _fmt_cache[fmt] = ops
  return ops
end
local double_to_bytes
double_to_bytes = function(n, le)
  local buf = ffi.new("double[1]", n)
  local b = ffi.cast("uint8_t *", buf)
  local bytes
  do
    local _tbl_0 = { }
    for i = 0, 7 do
      local _key_0, _val_0 = b[i]
      _tbl_0[_key_0] = _val_0
    end
    bytes = _tbl_0
  end
  if not le then
    bytes = {
      bytes[8],
      bytes[7],
      bytes[6],
      bytes[5],
      bytes[4],
      bytes[3],
      bytes[2],
      bytes[1]
    }
  end
  return bytes
end
local bytes_to_double
bytes_to_double = function(s, offset, le)
  local buf = ffi.new("uint8_t[8]")
  if le then
    for i = 0, 7 do
      buf[i] = string.byte(s, offset + i + 1)
    end
  else
    for i = 0, 7 do
      buf[i] = string.byte(s, offset + 7 - i + 1)
    end
  end
  local d = ffi.cast("double *", buf)
  return d[0]
end
local float_to_bytes
float_to_bytes = function(n, le)
  local buf = ffi.new("float[1]", n)
  local b = ffi.cast("uint8_t *", buf)
  local bytes
  do
    local _tbl_0 = { }
    for i = 0, 3 do
      local _key_0, _val_0 = b[i]
      _tbl_0[_key_0] = _val_0
    end
    bytes = _tbl_0
  end
  if not le then
    bytes = {
      bytes[4],
      bytes[3],
      bytes[2],
      bytes[1]
    }
  end
  return bytes
end
local bytes_to_float
bytes_to_float = function(s, offset, le)
  local buf = ffi.new("uint8_t[4]")
  if le then
    for i = 0, 3 do
      buf[i] = string.byte(s, offset + i + 1)
    end
  else
    for i = 0, 3 do
      buf[i] = string.byte(s, offset + 3 - i + 1)
    end
  end
  local f = ffi.cast("float *", buf)
  return tonumber(f[0])
end
local pack
pack = function(fmt, ...)
  local args = {
    ...
  }
  local argi = 1
  local parts = { }
  local ops = _fmt_cache[fmt] or parse_format_to_ops(fmt)
  for j = 1, #ops do
    local opt, count, le
    do
      local _obj_0 = ops[j]
      opt, count, le = _obj_0[1], _obj_0[2], _obj_0[3]
    end
    local _exp_0 = opt
    if "b" == _exp_0 then
      local v = args[argi]
      argi = argi + 1
      v = v % 256
      parts[#parts + 1] = string.char(v)
    elseif "B" == _exp_0 then
      local v = args[argi]
      argi = argi + 1
      parts[#parts + 1] = string.char(v % 256)
    elseif "h" == _exp_0 then
      local v = args[argi]
      argi = argi + 1
      local uv = v % 65536
      if le then
        parts[#parts + 1] = string.char(uv % 256, math.floor(uv / 256) % 256)
      else
        parts[#parts + 1] = string.char(math.floor(uv / 256) % 256, uv % 256)
      end
    elseif "H" == _exp_0 then
      local v = args[argi]
      argi = argi + 1
      local uv = v % 65536
      if le then
        parts[#parts + 1] = string.char(uv % 256, math.floor(uv / 256) % 256)
      else
        parts[#parts + 1] = string.char(math.floor(uv / 256) % 256, uv % 256)
      end
    elseif "i" == _exp_0 or "I" == _exp_0 then
      local sz = count or 4
      local v = args[argi]
      argi = argi + 1
      local buf = ffi.new("uint8_t[?]", sz)
      write_uint(buf, 0, v, sz, le)
      parts[#parts + 1] = ffi.string(buf, sz)
    elseif "l" == _exp_0 or "L" == _exp_0 or "j" == _exp_0 or "J" == _exp_0 or "T" == _exp_0 then
      local v = args[argi]
      argi = argi + 1
      local buf = ffi.new("uint8_t[8]")
      write_uint(buf, 0, v, 8, le)
      parts[#parts + 1] = ffi.string(buf, 8)
    elseif "f" == _exp_0 then
      local v = args[argi]
      argi = argi + 1
      local bytes = float_to_bytes(v, le)
      parts[#parts + 1] = string.char(tunpack(bytes))
    elseif "d" == _exp_0 or "n" == _exp_0 then
      local v = args[argi]
      argi = argi + 1
      local bytes = double_to_bytes(v, le)
      parts[#parts + 1] = string.char(tunpack(bytes))
    elseif "c" == _exp_0 then
      local sz = count or 1
      local v = args[argi]
      argi = argi + 1
      if #v < sz then
        parts[#parts + 1] = v .. string.rep("\0", sz - #v)
      else
        parts[#parts + 1] = v:sub(1, sz)
      end
    elseif "s" == _exp_0 then
      local sz = count or 8
      local v = args[argi]
      argi = argi + 1
      local buf = ffi.new("uint8_t[?]", sz)
      write_uint(buf, 0, #v, sz, le)
      parts[#parts + 1] = ffi.string(buf, sz) .. v
    elseif "z" == _exp_0 then
      local v = args[argi]
      argi = argi + 1
      parts[#parts + 1] = v .. "\0"
    elseif "x" == _exp_0 then
      parts[#parts + 1] = "\0"
    elseif "X" == _exp_0 then
      local _ = nil
    end
  end
  return table.concat(parts)
end
local _results = { }
local unpack
unpack = function(fmt, s, pos)
  pos = (pos or 1) - 1
  local n = 0
  local ops = _fmt_cache[fmt] or parse_format_to_ops(fmt)
  for j = 1, #ops do
    local opt, count, le
    do
      local _obj_0 = ops[j]
      opt, count, le = _obj_0[1], _obj_0[2], _obj_0[3]
    end
    local _exp_0 = opt
    if "b" == _exp_0 then
      local v = string.byte(s, pos + 1)
      n = n + 1
      _results[n] = to_signed(v, 1)
      pos = pos + 1
    elseif "B" == _exp_0 then
      n = n + 1
      _results[n] = string.byte(s, pos + 1)
      pos = pos + 1
    elseif "h" == _exp_0 then
      local uv = read_uint(s, pos, 2, le)
      n = n + 1
      _results[n] = to_signed(uv, 2)
      pos = pos + 2
    elseif "H" == _exp_0 then
      n = n + 1
      _results[n] = tonumber(read_uint(s, pos, 2, le))
      pos = pos + 2
    elseif "i" == _exp_0 then
      local sz = count or 4
      local uv = read_uint(s, pos, sz, le)
      n = n + 1
      _results[n] = to_signed(uv, sz)
      pos = pos + sz
    elseif "I" == _exp_0 then
      local sz = count or 4
      n = n + 1
      _results[n] = tonumber(read_uint(s, pos, sz, le))
      pos = pos + sz
    elseif "l" == _exp_0 then
      local uv = read_uint(s, pos, 8, le)
      n = n + 1
      _results[n] = tonumber(ffi.cast("int64_t", uv))
      pos = pos + 8
    elseif "L" == _exp_0 or "J" == _exp_0 or "T" == _exp_0 then
      n = n + 1
      _results[n] = tonumber(read_uint(s, pos, 8, le))
      pos = pos + 8
    elseif "j" == _exp_0 then
      local uv = read_uint(s, pos, 8, le)
      n = n + 1
      _results[n] = tonumber(ffi.cast("int64_t", uv))
      pos = pos + 8
    elseif "f" == _exp_0 then
      n = n + 1
      _results[n] = bytes_to_float(s, pos, le)
      pos = pos + 4
    elseif "d" == _exp_0 or "n" == _exp_0 then
      n = n + 1
      _results[n] = bytes_to_double(s, pos, le)
      pos = pos + 8
    elseif "c" == _exp_0 then
      local sz = count or 1
      n = n + 1
      _results[n] = s:sub(pos + 1, pos + sz)
      pos = pos + sz
    elseif "s" == _exp_0 then
      local sz = count or 8
      local len = tonumber(read_uint(s, pos, sz, le))
      pos = pos + sz
      n = n + 1
      _results[n] = s:sub(pos + 1, pos + len)
      pos = pos + len
    elseif "z" == _exp_0 then
      local nul = s:find("\0", pos + 1, true)
      if not nul then
        error("string.unpack 'z' : pas de \\0 trouvé")
      end
      n = n + 1
      _results[n] = s:sub(pos + 1, nul - 1)
      pos = nul
    elseif "x" == _exp_0 then
      pos = pos + 1
    elseif "X" == _exp_0 then
      local _ = nil
    end
  end
  n = n + 1
  _results[n] = pos + 1
  return tunpack(_results, 1, n)
end
local inject
inject = function()
  string.pack = pack
  string.unpack = unpack
  string.packsize = packsize
end
setmetatable({
  pack = pack,
  unpack = unpack,
  packsize = packsize,
  inject = inject
}, {
  __index = string
})
inject = function()
  string.pack = pack
  string.unpack = unpack
  string.packsize = packsize
end
return setmetatable({
  pack = pack,
  unpack = unpack,
  packsize = packsize,
  inject = inject
}, {
  __index = string
})
