if string.unpack then
  return string
end
local tunpack = unpack or table.unpack
local ok, ffi = pcall(require, "ffi")
local HAS_FFI = ok
if not (HAS_FFI) then
  ffi = nil
end
local NATIVE_LE = true
if HAS_FFI then
  local probe = ffi.new("uint16_t[1]", 0x0102)
  local pb = ffi.cast("uint8_t *", probe)
  NATIVE_LE = pb[0] == 0x02
end
local read_uint
read_uint = function(s, offset, size, le)
  if offset + size > #s then
    error("data string too short")
  end
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
  if HAS_FFI then
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
  else
    local val = 0
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
end
local cast_uint
cast_uint = function(val)
  if val < 0 then
    return ffi.cast("uint64_t", ffi.cast("int64_t", val))
  else
    return ffi.cast("uint64_t", val)
  end
end
local to_signed
to_signed = function(val, size)
  local uval
  if HAS_FFI then
    uval = tonumber(ffi.cast("uint64_t", val))
  else
    uval = val
  end
  local bits = size * 8
  local limit = 2 ^ (bits - 1)
  if uval >= limit then
    return uval - 2 ^ bits
  else
    return uval
  end
end
local read_int
read_int = function(s, offset, size, le)
  local u = read_uint(s, offset, size, le)
  local limit = 2 ^ (size * 8 - 1)
  if u < limit then
    return u
  end
  local mag = 0
  local carry = 1
  for i = 0, size - 1 do
    local idx
    if le then
      idx = offset + i + 1
    else
      idx = offset + size - i
    end
    local b = 255 - string.byte(s, idx) + carry
    if b >= 256 then
      b = b - 256
      carry = 1
    else
      carry = 0
    end
    mag = mag + (b * 2 ^ (8 * i))
  end
  return -mag
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
    return error("unknown format option: '" .. tostring(opt) .. "'")
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
      error("string.packsize: format '" .. tostring(opt) .. "' has variable size")
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
local round_even
round_even = function(x)
  local f = math.floor(x)
  local d = x - f
  if d > 0.5 or (d == 0.5 and f % 2 == 1) then
    return f + 1
  else
    return f
  end
end
local ieee_encode
ieee_encode = function(n, expbits, fracbits, bias, le)
  local maxexp = 2 ^ expbits - 1
  local sign = 0
  local exp = 0
  local frac = 0
  if n ~= n then
    exp = maxexp
    frac = 2 ^ (fracbits - 1)
  elseif n == math.huge or n == -math.huge then
    if n < 0 then
      sign = 1
    end
    exp = maxexp
    frac = 0
  elseif n == 0 then
    if 1 / n < 0 then
      sign = 1
    end
    exp = 0
    frac = 0
  else
    if n < 0 then
      sign = 1
    end
    local a = math.abs(n)
    local m, e = math.frexp(a)
    local E = e - 1 + bias
    if E <= 0 then
      frac = round_even(math.ldexp(m, e + fracbits + bias - 1))
      if frac >= 2 ^ fracbits then
        exp = 1
        frac = frac - (2 ^ fracbits)
      else
        exp = 0
      end
    else
      frac = round_even(math.ldexp((m * 2 - 1), fracbits))
      if frac >= 2 ^ fracbits then
        frac = frac - (2 ^ fracbits)
        E = E + 1
      end
      if E >= maxexp then
        exp = maxexp
        frac = 0
      else
        exp = E
      end
    end
  end
  local bytes = { }
  if fracbits == 52 then
    bytes[1] = sign * 128 + math.floor(exp / 16)
    bytes[2] = (exp % 16) * 16 + math.floor(frac / 2 ^ 48)
    bytes[3] = math.floor(frac / 2 ^ 40) % 256
    bytes[4] = math.floor(frac / 2 ^ 32) % 256
    bytes[5] = math.floor(frac / 2 ^ 24) % 256
    bytes[6] = math.floor(frac / 2 ^ 16) % 256
    bytes[7] = math.floor(frac / 2 ^ 8) % 256
    bytes[8] = frac % 256
  else
    bytes[1] = sign * 128 + math.floor(exp / 2)
    bytes[2] = (exp % 2) * 128 + math.floor(frac / 2 ^ 16)
    bytes[3] = math.floor(frac / 2 ^ 8) % 256
    bytes[4] = frac % 256
  end
  if le then
    local out = { }
    for i = 1, #bytes do
      out[i] = bytes[#bytes + 1 - i]
    end
    bytes = out
  end
  return bytes
end
local ieee_decode
ieee_decode = function(s, offset, expbits, fracbits, bias, le)
  local nbytes = (expbits + fracbits + 1) / 8
  if offset + nbytes > #s then
    error("data string too short")
  end
  local bytes = { }
  if le then
    for i = 1, nbytes do
      bytes[i] = string.byte(s, offset + nbytes - i + 1)
    end
  else
    for i = 1, nbytes do
      bytes[i] = string.byte(s, offset + i)
    end
  end
  local b0 = bytes[1]
  local sign = b0 >= 128 and -1 or 1
  local exp = 0
  local frac = 0
  local maxexp = 2 ^ expbits - 1
  local denorm_shift = 1 - bias - fracbits
  if fracbits == 52 then
    exp = (b0 % 128) * 16 + math.floor(bytes[2] / 16)
    frac = (bytes[2] % 16) * 2 ^ 48 + bytes[3] * 2 ^ 40 + bytes[4] * 2 ^ 32 + bytes[5] * 2 ^ 24 + bytes[6] * 2 ^ 16 + bytes[7] * 2 ^ 8 + bytes[8]
  else
    exp = (b0 % 128) * 2 + math.floor(bytes[2] / 128)
    frac = (bytes[2] % 128) * 2 ^ 16 + bytes[3] * 2 ^ 8 + bytes[4]
  end
  if exp == maxexp then
    if frac == 0 then
      return sign * math.huge
    else
      return 0 / 0
    end
  elseif exp == 0 then
    return sign * math.ldexp(frac, denorm_shift)
  else
    return sign * math.ldexp((1 + frac / 2 ^ fracbits), exp - bias)
  end
end
local double_to_bytes = nil
local bytes_to_double = nil
local float_to_bytes = nil
local bytes_to_float = nil
if HAS_FFI then
  double_to_bytes = function(n, le)
    local buf = ffi.new("double[1]", n)
    local b = ffi.cast("uint8_t *", buf)
    local bytes
    do
      local _accum_0 = { }
      local _len_0 = 1
      for i = 0, 7 do
        _accum_0[_len_0] = b[i]
        _len_0 = _len_0 + 1
      end
      bytes = _accum_0
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
  bytes_to_double = function(s, offset, le)
    if offset + 8 > #s then
      error("data string too short")
    end
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
  float_to_bytes = function(n, le)
    local buf = ffi.new("float[1]", n)
    local b = ffi.cast("uint8_t *", buf)
    local bytes
    do
      local _accum_0 = { }
      local _len_0 = 1
      for i = 0, 3 do
        _accum_0[_len_0] = b[i]
        _len_0 = _len_0 + 1
      end
      bytes = _accum_0
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
  bytes_to_float = function(s, offset, le)
    if offset + 4 > #s then
      error("data string too short")
    end
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
else
  double_to_bytes = function(n, le)
    return ieee_encode(n, 11, 52, 1023, le)
  end
  bytes_to_double = function(s, offset, le)
    return ieee_decode(s, offset, 11, 52, 1023, le)
  end
  float_to_bytes = function(n, le)
    return ieee_encode(n, 8, 23, 127, le)
  end
  bytes_to_float = function(s, offset, le)
    return ieee_decode(s, offset, 8, 23, 127, le)
  end
end
local _buf = { }
local _args = { }
local buf_string
buf_string = function(buf, n)
  if n <= 4096 then
    return string.char(tunpack(buf, 1, n))
  else
    local out = { }
    local i = 0
    while i < n do
      local len = math.min(4096, n - i)
      out[#out + 1] = string.char(tunpack(buf, i + 1, i + len))
      i = i + len
    end
    return table.concat(out)
  end
end
local append_string
append_string = function(parts, s)
  if not (parts) then
    parts = { }
  end
  parts[#parts + 1] = s
  return parts
end
local make_uint
make_uint = function(sz, le)
  if sz == 1 then
    return function(buf, n, v)
      buf[n + 1] = v % 256
      return n + 1
    end
  elseif sz == 2 then
    if le then
      return function(buf, n, v)
        local u = v % 65536
        buf[n + 1] = u % 256
        buf[n + 2] = math.floor(u / 256) % 256
        return n + 2
      end
    else
      return function(buf, n, v)
        local u = v % 65536
        buf[n + 1] = math.floor(u / 256) % 256
        buf[n + 2] = u % 256
        return n + 2
      end
    end
  elseif sz == 3 then
    local mod = 16777216
    if le then
      return function(buf, n, v)
        local u = v % mod
        buf[n + 1] = u % 256
        buf[n + 2] = math.floor(u / 256) % 256
        buf[n + 3] = math.floor(u / 65536) % 256
        return n + 3
      end
    else
      return function(buf, n, v)
        local u = v % mod
        buf[n + 1] = math.floor(u / 65536) % 256
        buf[n + 2] = math.floor(u / 256) % 256
        buf[n + 3] = u % 256
        return n + 3
      end
    end
  elseif sz == 4 then
    local mod = 4294967296
    if le then
      return function(buf, n, v)
        local u = v % mod
        buf[n + 1] = u % 256
        buf[n + 2] = math.floor(u / 256) % 256
        buf[n + 3] = math.floor(u / 65536) % 256
        buf[n + 4] = math.floor(u / 16777216) % 256
        return n + 4
      end
    else
      return function(buf, n, v)
        local u = v % mod
        buf[n + 1] = math.floor(u / 16777216) % 256
        buf[n + 2] = math.floor(u / 65536) % 256
        buf[n + 3] = math.floor(u / 256) % 256
        buf[n + 4] = u % 256
        return n + 4
      end
    end
  elseif sz <= 6 then
    local mod = 2 ^ (8 * sz)
    if le then
      return function(buf, n, v)
        local u = v % mod
        for k = 1, sz do
          buf[n + k] = u % 256
          u = math.floor(u / 256)
        end
        return n + sz
      end
    else
      return function(buf, n, v)
        local u = v % mod
        for k = sz, 1, -1 do
          buf[n + k] = u % 256
          u = math.floor(u / 256)
        end
        return n + sz
      end
    end
  elseif not HAS_FFI then
    if le then
      return function(buf, n, v)
        local p = 1
        for k = 1, sz do
          buf[n + k] = math.floor(v / p) % 256
          p = p * 256
        end
        return n + sz
      end
    else
      return function(buf, n, v)
        local p = 256 ^ (sz - 1)
        for k = 1, sz do
          buf[n + k] = math.floor(v / p) % 256
          p = p / 256
        end
        return n + sz
      end
    end
  else
    if le then
      return function(buf, n, v)
        local u = cast_uint(v)
        for k = 1, sz do
          buf[n + k] = tonumber(u % 256)
          u = u / 256
        end
        return n + sz
      end
    else
      return function(buf, n, v)
        local u = cast_uint(v)
        for k = sz, 1, -1 do
          buf[n + k] = tonumber(u % 256)
          u = u / 256
        end
        return n + sz
      end
    end
  end
end
local make_float
make_float = function(le)
  return function(v)
    return string.char(tunpack(float_to_bytes(v, le)))
  end
end
local make_double
make_double = function(le)
  return function(v)
    return string.char(tunpack(double_to_bytes(v, le)))
  end
end
local make_c
make_c = function(sz)
  return function(v)
    if #v < sz then
      return v .. string.rep("\0", sz - #v)
    else
      return v:sub(1, sz)
    end
  end
end
local pack_op
pack_op = function(opt, count, le)
  local _exp_0 = opt
  if "b" == _exp_0 or "B" == _exp_0 then
    return {
      consume = true,
      write = make_uint(1, le)
    }
  elseif "h" == _exp_0 or "H" == _exp_0 then
    return {
      consume = true,
      write = make_uint(2, le)
    }
  elseif "i" == _exp_0 or "I" == _exp_0 then
    return {
      consume = true,
      write = make_uint((count or 4), le)
    }
  elseif "l" == _exp_0 or "L" == _exp_0 or "j" == _exp_0 or "J" == _exp_0 or "T" == _exp_0 then
    return {
      consume = true,
      write = make_uint(8, le)
    }
  elseif "f" == _exp_0 then
    return {
      consume = true,
      emit = make_float(le)
    }
  elseif "d" == _exp_0 or "n" == _exp_0 then
    return {
      consume = true,
      emit = make_double(le)
    }
  elseif "c" == _exp_0 then
    return {
      consume = true,
      emit = make_c(count or 1)
    }
  elseif "s" == _exp_0 then
    return {
      consume = true,
      write_len = make_uint((count or 8), le),
      emit = function(v)
        return v
      end
    }
  elseif "z" == _exp_0 then
    return {
      consume = true,
      emit = function(v)
        return v .. "\0"
      end
    }
  elseif "x" == _exp_0 then
    return {
      consume = false,
      write = function(buf, n)
        buf[n + 1] = 0
        return n + 1
      end
    }
  else
    return {
      consume = false,
      write = function(buf, n)
        return n
      end
    }
  end
end
local _pack_cache = { }
local compile_pack
compile_pack = function(fmt)
  local plan = { }
  local consumed = 0
  local iter = parse_format(fmt)
  local opt, count, le = iter()
  while opt ~= nil do
    local op = pack_op(opt, count, le)
    plan[#plan + 1] = op
    if op.consume then
      consumed = consumed + 1
    end
    opt, count, le = iter()
  end
  plan.count = consumed
  local tail = nil
  if #plan > 0 then
    local last = plan[#plan]
    if last.consume and last.emit and not last.write then
      ok = true
      for k = 1, #plan - 1 do
        local prev = plan[k]
        if not (prev.write and not prev.emit) then
          ok = false
        end
      end
      if ok then
        tail = last
      end
    end
  end
  plan.tail = tail
  _pack_cache[fmt] = plan
  return plan
end
local pack
pack = function(fmt, a1, a2, a3, a4, a5, a6, a7, a8, ...)
  local plan = _pack_cache[fmt] or compile_pack(fmt)
  local args = nil
  if plan.count > 8 then
    args = {
      a1,
      a2,
      a3,
      a4,
      a5,
      a6,
      a7,
      a8,
      ...
    }
  else
    args = _args
    args[1] = a1
    args[2] = a2
    args[3] = a3
    args[4] = a4
    args[5] = a5
    args[6] = a6
    args[7] = a7
    args[8] = a8
  end
  local n = 0
  local parts = nil
  local argi = 1
  local last = plan.tail
  local limit = last and (#plan - 1) or #plan
  for j = 1, limit do
    local op = plan[j]
    if op.write then
      if op.consume then
        n = op.write(_buf, n, args[argi])
        argi = argi + 1
      else
        n = op.write(_buf, n)
      end
    else
      local v = args[argi]
      argi = argi + 1
      if op.write_len then
        n = op.write_len(_buf, n, #v)
      end
      if n > 0 then
        parts = append_string(parts, buf_string(_buf, n))
        n = 0
      end
      parts = append_string(parts, op.emit(v))
    end
  end
  local result = nil
  if last then
    local v = args[argi]
    if last.write_len then
      n = last.write_len(_buf, n, #v)
    end
    result = buf_string(_buf, n) .. last.emit(v)
  elseif parts then
    if n > 0 then
      parts = append_string(parts, buf_string(_buf, n))
    end
    result = table.concat(parts)
  else
    result = buf_string(_buf, n)
  end
  return result
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
      if pos + 1 > #s then
        error("data string too short")
      end
      local v = string.byte(s, pos + 1)
      n = n + 1
      _results[n] = to_signed(v, 1)
      pos = pos + 1
    elseif "B" == _exp_0 then
      if pos + 1 > #s then
        error("data string too short")
      end
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
      n = n + 1
      if not HAS_FFI then
        _results[n] = read_int(s, pos, sz, le)
      elseif sz == 8 then
        _results[n] = tonumber(ffi.cast("int64_t", read_uint(s, pos, 8, le)))
      else
        local uv = read_uint(s, pos, sz, le)
        _results[n] = to_signed(uv, sz)
      end
      pos = pos + sz
    elseif "I" == _exp_0 then
      local sz = count or 4
      n = n + 1
      _results[n] = tonumber(read_uint(s, pos, sz, le))
      pos = pos + sz
    elseif "l" == _exp_0 then
      n = n + 1
      if HAS_FFI then
        _results[n] = tonumber(ffi.cast("int64_t", read_uint(s, pos, 8, le)))
      else
        _results[n] = read_int(s, pos, 8, le)
      end
      pos = pos + 8
    elseif "L" == _exp_0 or "J" == _exp_0 or "T" == _exp_0 then
      n = n + 1
      _results[n] = tonumber(read_uint(s, pos, 8, le))
      pos = pos + 8
    elseif "j" == _exp_0 then
      n = n + 1
      if HAS_FFI then
        _results[n] = tonumber(ffi.cast("int64_t", read_uint(s, pos, 8, le)))
      else
        _results[n] = read_int(s, pos, 8, le)
      end
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
      if pos + sz > #s then
        error("data string too short")
      end
      n = n + 1
      _results[n] = s:sub(pos + 1, pos + sz)
      pos = pos + sz
    elseif "s" == _exp_0 then
      local sz = count or 8
      local len = tonumber(read_uint(s, pos, sz, le))
      pos = pos + sz
      if pos + len > #s then
        error("data string too short")
      end
      n = n + 1
      _results[n] = s:sub(pos + 1, pos + len)
      pos = pos + len
    elseif "z" == _exp_0 then
      local nul = s:find("\0", pos + 1, true)
      if not nul then
        error("string.unpack 'z': no \\0 found")
      end
      n = n + 1
      _results[n] = s:sub(pos + 1, nul - 1)
      pos = nul
    elseif "x" == _exp_0 then
      if pos + 1 > #s then
        error("data string too short")
      end
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
return setmetatable({
  pack = pack,
  unpack = unpack,
  packsize = packsize,
  inject = inject
}, {
  __index = string
})
