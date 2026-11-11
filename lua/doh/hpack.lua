local bit = require("bit")
local STATIC_TABLE = {
  {
    ":authority",
    ""
  },
  {
    ":method",
    "GET"
  },
  {
    ":method",
    "POST"
  },
  {
    ":path",
    "/"
  },
  {
    ":path",
    "/index.html"
  },
  {
    ":scheme",
    "http"
  },
  {
    ":scheme",
    "https"
  },
  {
    ":status",
    "200"
  },
  {
    ":status",
    "204"
  },
  {
    ":status",
    "206"
  },
  {
    ":status",
    "304"
  },
  {
    ":status",
    "400"
  },
  {
    ":status",
    "404"
  },
  {
    ":status",
    "500"
  },
  {
    "accept-charset",
    ""
  },
  {
    "accept-encoding",
    "gzip, deflate"
  },
  {
    "accept-language",
    ""
  },
  {
    "accept-ranges",
    ""
  },
  {
    "accept",
    ""
  },
  {
    "access-control-allow-origin",
    ""
  },
  {
    "age",
    ""
  },
  {
    "allow",
    ""
  },
  {
    "authorization",
    ""
  },
  {
    "cache-control",
    ""
  },
  {
    "content-disposition",
    ""
  },
  {
    "content-encoding",
    ""
  },
  {
    "content-language",
    ""
  },
  {
    "content-length",
    ""
  },
  {
    "content-location",
    ""
  },
  {
    "content-range",
    ""
  },
  {
    "content-type",
    ""
  },
  {
    "cookie",
    ""
  },
  {
    "date",
    ""
  },
  {
    "etag",
    ""
  },
  {
    "expect",
    ""
  },
  {
    "expires",
    ""
  },
  {
    "from",
    ""
  },
  {
    "host",
    ""
  },
  {
    "if-match",
    ""
  },
  {
    "if-modified-since",
    ""
  },
  {
    "if-none-match",
    ""
  },
  {
    "if-range",
    ""
  },
  {
    "if-unmodified-since",
    ""
  },
  {
    "last-modified",
    ""
  },
  {
    "link",
    ""
  },
  {
    "location",
    ""
  },
  {
    "max-forwards",
    ""
  },
  {
    "proxy-authenticate",
    ""
  },
  {
    "proxy-authorization",
    ""
  },
  {
    "range",
    ""
  },
  {
    "referer",
    ""
  },
  {
    "refresh",
    ""
  },
  {
    "retry-after",
    ""
  },
  {
    "server",
    ""
  },
  {
    "set-cookie",
    ""
  },
  {
    "strict-transport-security",
    ""
  },
  {
    "transfer-encoding",
    ""
  },
  {
    "user-agent",
    ""
  },
  {
    "vary",
    ""
  },
  {
    "via",
    ""
  },
  {
    "www-authenticate",
    ""
  }
}
local HUFFMAN_TABLE = {
  {
    0x1ff8,
    13
  },
  {
    0x7fffd8,
    23
  },
  {
    0xfffffe2,
    28
  },
  {
    0xfffffe3,
    28
  },
  {
    0xfffffe4,
    28
  },
  {
    0xfffffe5,
    28
  },
  {
    0xfffffe6,
    28
  },
  {
    0xfffffe7,
    28
  },
  {
    0xfffffe8,
    28
  },
  {
    0xffffea,
    24
  },
  {
    0x3ffffffc,
    30
  },
  {
    0xfffffe9,
    28
  },
  {
    0xfffffea,
    28
  },
  {
    0x3ffffffd,
    30
  },
  {
    0xfffffeb,
    28
  },
  {
    0xfffffec,
    28
  },
  {
    0xfffffed,
    28
  },
  {
    0xfffffee,
    28
  },
  {
    0xfffffef,
    28
  },
  {
    0xffffff0,
    28
  },
  {
    0xffffff1,
    28
  },
  {
    0xffffff2,
    28
  },
  {
    0x3ffffffe,
    30
  },
  {
    0xffffff3,
    28
  },
  {
    0xffffff4,
    28
  },
  {
    0xffffff5,
    28
  },
  {
    0xffffff6,
    28
  },
  {
    0xffffff7,
    28
  },
  {
    0xffffff8,
    28
  },
  {
    0xffffff9,
    28
  },
  {
    0xffffffa,
    28
  },
  {
    0xffffffb,
    28
  },
  {
    0x14,
    6
  },
  {
    0x3f8,
    10
  },
  {
    0x3f9,
    10
  },
  {
    0xffa,
    12
  },
  {
    0x1ff9,
    13
  },
  {
    0x15,
    6
  },
  {
    0xf8,
    8
  },
  {
    0x7fa,
    11
  },
  {
    0x3fa,
    10
  },
  {
    0x3fb,
    10
  },
  {
    0xf9,
    8
  },
  {
    0x7fb,
    11
  },
  {
    0xfa,
    8
  },
  {
    0x16,
    6
  },
  {
    0x17,
    6
  },
  {
    0x18,
    6
  },
  {
    0x0,
    5
  },
  {
    0x1,
    5
  },
  {
    0x2,
    5
  },
  {
    0x19,
    6
  },
  {
    0x1a,
    6
  },
  {
    0x1b,
    6
  },
  {
    0x1c,
    6
  },
  {
    0x1d,
    6
  },
  {
    0x1e,
    6
  },
  {
    0x1f,
    6
  },
  {
    0x5c,
    7
  },
  {
    0xfb,
    8
  },
  {
    0x7ffc,
    15
  },
  {
    0x20,
    6
  },
  {
    0xffb,
    12
  },
  {
    0x3fc,
    10
  },
  {
    0x1ffa,
    13
  },
  {
    0x21,
    6
  },
  {
    0x5d,
    7
  },
  {
    0x5e,
    7
  },
  {
    0x5f,
    7
  },
  {
    0x60,
    7
  },
  {
    0x61,
    7
  },
  {
    0x62,
    7
  },
  {
    0x63,
    7
  },
  {
    0x64,
    7
  },
  {
    0x65,
    7
  },
  {
    0x66,
    7
  },
  {
    0x67,
    7
  },
  {
    0x68,
    7
  },
  {
    0x69,
    7
  },
  {
    0x6a,
    7
  },
  {
    0x6b,
    7
  },
  {
    0x6c,
    7
  },
  {
    0x6d,
    7
  },
  {
    0x6e,
    7
  },
  {
    0x6f,
    7
  },
  {
    0x70,
    7
  },
  {
    0x71,
    7
  },
  {
    0x72,
    7
  },
  {
    0xfc,
    8
  },
  {
    0x73,
    7
  },
  {
    0xfd,
    8
  },
  {
    0x1ffb,
    13
  },
  {
    0x7fff0,
    19
  },
  {
    0x1ffc,
    13
  },
  {
    0x3ffc,
    14
  },
  {
    0x22,
    6
  },
  {
    0x7ffd,
    15
  },
  {
    0x3,
    5
  },
  {
    0x23,
    6
  },
  {
    0x4,
    5
  },
  {
    0x24,
    6
  },
  {
    0x5,
    5
  },
  {
    0x25,
    6
  },
  {
    0x26,
    6
  },
  {
    0x27,
    6
  },
  {
    0x6,
    5
  },
  {
    0x74,
    7
  },
  {
    0x75,
    7
  },
  {
    0x28,
    6
  },
  {
    0x29,
    6
  },
  {
    0x2a,
    6
  },
  {
    0x7,
    5
  },
  {
    0x2b,
    6
  },
  {
    0x76,
    7
  },
  {
    0x2c,
    6
  },
  {
    0x8,
    5
  },
  {
    0x9,
    5
  },
  {
    0x2d,
    6
  },
  {
    0x77,
    7
  },
  {
    0x78,
    7
  },
  {
    0x79,
    7
  },
  {
    0x7a,
    7
  },
  {
    0x7b,
    7
  },
  {
    0x7ffe,
    15
  },
  {
    0x7fc,
    11
  },
  {
    0x3ffd,
    14
  },
  {
    0x1ffd,
    13
  },
  {
    0xffffffc,
    28
  },
  {
    0xfffe6,
    20
  },
  {
    0x3fffd2,
    22
  },
  {
    0xfffe7,
    20
  },
  {
    0xfffe8,
    20
  },
  {
    0x3fffd3,
    22
  },
  {
    0x3fffd4,
    22
  },
  {
    0x3fffd5,
    22
  },
  {
    0x7fffd9,
    23
  },
  {
    0x3fffd6,
    22
  },
  {
    0x7fffda,
    23
  },
  {
    0x7fffdb,
    23
  },
  {
    0x7fffdc,
    23
  },
  {
    0x7fffdd,
    23
  },
  {
    0x7fffde,
    23
  },
  {
    0xffffeb,
    24
  },
  {
    0x7fffdf,
    23
  },
  {
    0xffffec,
    24
  },
  {
    0xffffed,
    24
  },
  {
    0x3fffd7,
    22
  },
  {
    0x7fffe0,
    23
  },
  {
    0xffffee,
    24
  },
  {
    0x7fffe1,
    23
  },
  {
    0x7fffe2,
    23
  },
  {
    0x7fffe3,
    23
  },
  {
    0x7fffe4,
    23
  },
  {
    0x1fffdc,
    21
  },
  {
    0x3fffd8,
    22
  },
  {
    0x7fffe5,
    23
  },
  {
    0x3fffd9,
    22
  },
  {
    0x7fffe6,
    23
  },
  {
    0x7fffe7,
    23
  },
  {
    0xffffef,
    24
  },
  {
    0x3fffda,
    22
  },
  {
    0x1fffdd,
    21
  },
  {
    0xfffe9,
    20
  },
  {
    0x3fffdb,
    22
  },
  {
    0x3fffdc,
    22
  },
  {
    0x7fffe8,
    23
  },
  {
    0x7fffe9,
    23
  },
  {
    0x1fffde,
    21
  },
  {
    0x7fffea,
    23
  },
  {
    0x3fffdd,
    22
  },
  {
    0x3fffde,
    22
  },
  {
    0xfffff0,
    24
  },
  {
    0x1fffdf,
    21
  },
  {
    0x3fffdf,
    22
  },
  {
    0x7fffeb,
    23
  },
  {
    0x7fffec,
    23
  },
  {
    0x1fffe0,
    21
  },
  {
    0x1fffe1,
    21
  },
  {
    0x3fffe0,
    22
  },
  {
    0x1fffe2,
    21
  },
  {
    0x7fffed,
    23
  },
  {
    0x3fffe1,
    22
  },
  {
    0x7fffee,
    23
  },
  {
    0x7fffef,
    23
  },
  {
    0xfffea,
    20
  },
  {
    0x3fffe2,
    22
  },
  {
    0x3fffe3,
    22
  },
  {
    0x3fffe4,
    22
  },
  {
    0x7ffff0,
    23
  },
  {
    0x3fffe5,
    22
  },
  {
    0x3fffe6,
    22
  },
  {
    0x7ffff1,
    23
  },
  {
    0x3ffffe0,
    26
  },
  {
    0x3ffffe1,
    26
  },
  {
    0xfffeb,
    20
  },
  {
    0x7fff1,
    19
  },
  {
    0x3fffe7,
    22
  },
  {
    0x7ffff2,
    23
  },
  {
    0x3fffe8,
    22
  },
  {
    0x1ffffec,
    25
  },
  {
    0x3ffffe2,
    26
  },
  {
    0x3ffffe3,
    26
  },
  {
    0x3ffffe4,
    26
  },
  {
    0x7ffffde,
    27
  },
  {
    0x7ffffdf,
    27
  },
  {
    0x3ffffe5,
    26
  },
  {
    0xfffff1,
    24
  },
  {
    0x1ffffed,
    25
  },
  {
    0x7fff2,
    19
  },
  {
    0x1fffe3,
    21
  },
  {
    0x3ffffe6,
    26
  },
  {
    0x7ffffe0,
    27
  },
  {
    0x7ffffe1,
    27
  },
  {
    0x3ffffe7,
    26
  },
  {
    0x7ffffe2,
    27
  },
  {
    0xfffff2,
    24
  },
  {
    0x1fffe4,
    21
  },
  {
    0x1fffe5,
    21
  },
  {
    0x3ffffe8,
    26
  },
  {
    0x3ffffe9,
    26
  },
  {
    0xffffffd,
    28
  },
  {
    0x7ffffe3,
    27
  },
  {
    0x7ffffe4,
    27
  },
  {
    0x7ffffe5,
    27
  },
  {
    0xfffec,
    20
  },
  {
    0xfffff3,
    24
  },
  {
    0xfffed,
    20
  },
  {
    0x1fffe6,
    21
  },
  {
    0x3fffe9,
    22
  },
  {
    0x1fffe7,
    21
  },
  {
    0x1fffe8,
    21
  },
  {
    0x7ffff3,
    23
  },
  {
    0x3fffea,
    22
  },
  {
    0x3fffeb,
    22
  },
  {
    0x1ffffee,
    25
  },
  {
    0x1ffffef,
    25
  },
  {
    0xfffff4,
    24
  },
  {
    0xfffff5,
    24
  },
  {
    0x3ffffea,
    26
  },
  {
    0x7ffff4,
    23
  },
  {
    0x3ffffeb,
    26
  },
  {
    0x7ffffe6,
    27
  },
  {
    0x3ffffec,
    26
  },
  {
    0x3ffffed,
    26
  },
  {
    0x7ffffe7,
    27
  },
  {
    0x7ffffe8,
    27
  },
  {
    0x7ffffe9,
    27
  },
  {
    0x7ffffea,
    27
  },
  {
    0x7ffffeb,
    27
  },
  {
    0xffffffe,
    28
  },
  {
    0x7ffffec,
    27
  },
  {
    0x7ffffed,
    27
  },
  {
    0x7ffffee,
    27
  },
  {
    0x7ffffef,
    27
  },
  {
    0x7fffff0,
    27
  },
  {
    0x3ffffee,
    26
  },
  {
    0x3fffffff,
    30
  }
}
local static_name_index = { }
local static_exact_index = { }
for i = 1, #STATIC_TABLE do
  local name = STATIC_TABLE[i][1]
  local value = STATIC_TABLE[i][2]
  if not (static_name_index[name]) then
    static_name_index[name] = i
  end
  static_exact_index[tostring(name) .. "\0" .. tostring(value)] = i
end
local _huffman_root = nil
local huffman_tree
huffman_tree = function()
  if _huffman_root then
    return _huffman_root
  end
  local root = { }
  for sym = 0, 256 do
    local entry = HUFFMAN_TABLE[sym + 1]
    local code = entry[1]
    local bits = entry[2]
    local node = root
    for i = bits - 1, 0, -1 do
      local b = bit.band(bit.rshift(code, i), 1)
      local child = node[b]
      if not (child) then
        child = { }
        node[b] = child
      end
      node = child
    end
    node.sym = sym
  end
  _huffman_root = root
  return root
end
local huffman_decode
huffman_decode = function(s, max_len)
  local out = { }
  local node = huffman_tree()
  local pending = 0
  local pending_ones = true
  for i = 1, #s do
    local byte = s:byte(i)
    for b = 7, 0, -1 do
      local v = bit.band(bit.rshift(byte, b), 1)
      node = node[v]
      if not (node) then
        return nil, "huffman_invalid_code"
      end
      pending = pending + 1
      if v == 0 then
        pending_ones = false
      end
      if node.sym ~= nil then
        local sym = node.sym
        if sym == 256 then
          return nil, "huffman_eos"
        end
        out[#out + 1] = string.char(sym)
        if max_len and #out > max_len then
          return nil, "string_too_long"
        end
        node = huffman_tree()
        pending = 0
        pending_ones = true
      end
    end
  end
  if node ~= huffman_tree() then
    if pending > 7 or not pending_ones then
      return nil, "huffman_invalid_padding"
    end
  end
  return table.concat(out)
end
local decode_integer
decode_integer = function(s, pos, prefix_bits)
  if pos > #s then
    return nil, nil, "truncated_integer"
  end
  local mask = bit.lshift(1, prefix_bits) - 1
  local value = bit.band(s:byte(pos), mask)
  pos = pos + 1
  if value < mask then
    return value, pos, nil
  end
  local shift = 0
  local cont = 0
  while true do
    if pos > #s then
      return nil, nil, "truncated_integer"
    end
    local b = s:byte(pos)
    pos = pos + 1
    cont = cont + 1
    if cont > 5 then
      return nil, nil, "integer_too_long"
    end
    value = value + bit.lshift(bit.band(b, 0x7f), shift)
    if value > 0x7fffffff then
      return nil, nil, "integer_too_long"
    end
    shift = shift + 7
    if bit.band(b, 0x80) == 0 then
      break
    end
  end
  return value, pos, nil
end
local decode_string
decode_string = function(s, pos, max_len)
  if pos > #s then
    return nil, nil, "truncated_string"
  end
  local huffman = bit.band(s:byte(pos), 0x80) ~= 0
  local len, err
  len, pos, err = decode_integer(s, pos, 7)
  if err then
    return nil, nil, err
  end
  if max_len and len > max_len then
    return nil, nil, "string_too_long"
  end
  if pos + len - 1 > #s then
    return nil, nil, "truncated_string"
  end
  local raw = s:sub(pos, pos + len - 1)
  pos = pos + len
  if huffman then
    local decoded, derr = huffman_decode(raw, max_len)
    if derr then
      return nil, nil, derr
    end
    return decoded, pos, nil
  end
  return raw, pos, nil
end
local table_entry
table_entry = function(decoder, index)
  if index >= 1 and index <= #STATIC_TABLE then
    return STATIC_TABLE[index][1], STATIC_TABLE[index][2]
  end
  local di = index - #STATIC_TABLE
  local entry = decoder.entries[di]
  if not (entry) then
    return nil
  end
  return entry[1], entry[2]
end
local evict
evict = function(decoder)
  while decoder.size > decoder.max_size and #decoder.entries > 0 do
    local last = table.remove(decoder.entries)
    decoder.size = decoder.size - last[3]
  end
end
local add_dynamic
add_dynamic = function(decoder, name, value)
  local entry_size = #name + #value + 32
  table.insert(decoder.entries, 1, {
    name,
    value,
    entry_size
  })
  decoder.size = decoder.size + entry_size
  return evict(decoder)
end
local decode_literal
decode_literal = function(decoder, block, pos, prefix_bits)
  local idx, err
  idx, pos, err = decode_integer(block, pos, prefix_bits)
  if err then
    return nil, nil, nil, err
  end
  local name = nil
  if idx == 0 then
    name, pos, err = decode_string(block, pos, decoder.max_header_size)
    if err then
      return nil, nil, nil, err
    end
  else
    name = table_entry(decoder, idx)
    if not (name) then
      return nil, nil, nil, "index_out_of_range"
    end
  end
  local value
  value, pos, err = decode_string(block, pos, decoder.max_header_size)
  if err then
    return nil, nil, nil, err
  end
  return name, value, pos, nil
end
local append_header
append_header = function(decoder, headers, name, value)
  decoder.header_size = decoder.header_size + #name + #value + 32
  if decoder.header_size > decoder.max_header_size then
    return nil, "header_list_too_large"
  end
  headers[#headers + 1] = {
    name,
    value
  }
  return true
end
local new_decoder
new_decoder = function(opts)
  if opts == nil then
    opts = { }
  end
  local max_size = opts.max_table_size or 4096
  return {
    entries = { },
    size = 0,
    max_size = max_size,
    allowed_max_size = max_size,
    max_header_size = opts.max_header_size or 16384,
    header_size = 0
  }
end
local decode
decode = function(decoder, block)
  local headers = { }
  decoder.header_size = 0
  local pos = 1
  local seen_header = false
  while pos <= #block do
    local b = block:byte(pos)
    if bit.band(b, 0x80) ~= 0 then
      local idx, err
      idx, pos, err = decode_integer(block, pos, 7)
      if err then
        return nil, err
      end
      if idx == 0 then
        return nil, "index_zero"
      end
      local name, value = table_entry(decoder, idx)
      if not (name) then
        return nil, "index_out_of_range"
      end
      local ok, aerr = append_header(decoder, headers, name, value)
      if not (ok) then
        return nil, aerr
      end
      seen_header = true
    elseif bit.band(b, 0x40) ~= 0 then
      local name, value, err
      name, value, pos, err = decode_literal(decoder, block, pos, 6)
      if err then
        return nil, err
      end
      add_dynamic(decoder, name, value)
      local ok, aerr = append_header(decoder, headers, name, value)
      if not (ok) then
        return nil, aerr
      end
      seen_header = true
    elseif bit.band(b, 0x20) ~= 0 then
      if seen_header then
        return nil, "dynamic_table_size_update_invalid"
      end
      local size, err
      size, pos, err = decode_integer(block, pos, 5)
      if err then
        return nil, err
      end
      if size > decoder.allowed_max_size then
        return nil, "dynamic_table_size_update_too_large"
      end
      decoder.max_size = size
      evict(decoder)
    else
      local name, value, err
      name, value, pos, err = decode_literal(decoder, block, pos, 4)
      if err then
        return nil, err
      end
      local ok, aerr = append_header(decoder, headers, name, value)
      if not (ok) then
        return nil, aerr
      end
      seen_header = true
    end
  end
  return headers
end
local encode_integer
encode_integer = function(value, prefix_bits, flags)
  local max = bit.lshift(1, prefix_bits) - 1
  if value < max then
    return string.char(bit.bor(flags, value))
  end
  local parts = {
    string.char(bit.bor(flags, max))
  }
  value = value - max
  while value >= 128 do
    parts[#parts + 1] = string.char(bit.bor(bit.band(value, 0x7f), 0x80))
    value = bit.rshift(value, 7)
  end
  parts[#parts + 1] = string.char(value)
  return table.concat(parts)
end
local encode_string
encode_string = function(s)
  return encode_integer(#s, 7, 0) .. s
end
local encode
encode = function(headers)
  local parts = { }
  for _index_0 = 1, #headers do
    local pair = headers[_index_0]
    local name = pair[1]
    local value = pair[2]
    local exact = static_exact_index[tostring(name) .. "\0" .. tostring(value)]
    if exact then
      parts[#parts + 1] = string.char(bit.bor(0x80, exact))
    else
      local name_idx = static_name_index[name] or 0
      parts[#parts + 1] = encode_integer(name_idx, 4, 0)
      if name_idx == 0 then
        parts[#parts + 1] = encode_string(name)
      end
      parts[#parts + 1] = encode_string(value)
    end
  end
  return table.concat(parts)
end
local header_value
header_value = function(headers, name)
  for _index_0 = 1, #headers do
    local pair = headers[_index_0]
    if pair[1] == name then
      return pair[2]
    end
  end
  return nil
end
return {
  STATIC_TABLE = STATIC_TABLE,
  HUFFMAN_TABLE = HUFFMAN_TABLE,
  new_decoder = new_decoder,
  decode = decode,
  encode = encode,
  encode_integer = encode_integer,
  decode_integer = decode_integer,
  decode_string = decode_string,
  huffman_decode = huffman_decode,
  header_value = header_value
}
