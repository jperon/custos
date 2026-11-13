local encode_ip16
encode_ip16 = function(ip_raw)
  if not (type(ip_raw) == "string") then
    return nil
  end
  if #ip_raw == 16 then
    return ip_raw
  end
  if #ip_raw == 4 then
    return ip_raw .. "\0\0\0\0\0\0\0\0\0\0\0\0"
  end
  return nil
end
local HEX_BYTE = { }
for i = 0, 255 do
  HEX_BYTE[string.char(i)] = string.format("%02x", i)
end
local CACHE_MAX_ENTRIES = 8
local CACHE_MAX_INPUT = 256
local _hex_enc_cache = { }
local _hex_enc_n = 0
local _hex_dec_cache = { }
local _hex_dec_n = 0
local to_hex
to_hex = function(s)
  if not (s and #s > 0) then
    return ""
  end
  local hit = _hex_enc_cache[s]
  if hit then
    return hit
  end
  local out = (s:gsub(".", HEX_BYTE))
  if #s <= CACHE_MAX_INPUT then
    if _hex_enc_n >= CACHE_MAX_ENTRIES then
      _hex_enc_cache = { }
      _hex_enc_n = 0
    end
    _hex_enc_cache[s] = out
    _hex_enc_n = _hex_enc_n + 1
  end
  return out
end
local HEX_VAL = { }
for i = 0, 9 do
  HEX_VAL[string.byte("0") + i] = i
end
for i = 0, 5 do
  HEX_VAL[string.byte("a") + i] = 10 + i
  HEX_VAL[string.byte("A") + i] = 10 + i
end
local from_hex
from_hex = function(h)
  if not h or #h == 0 then
    return "", nil
  end
  local hit = _hex_dec_cache[h]
  if hit then
    return hit, nil
  end
  local n = #h
  if (n % 2) ~= 0 then
    return nil, "hex_odd_length"
  end
  local out = { }
  local j = 1
  local i = 1
  while i <= n do
    local hi = HEX_VAL[h:byte(i)]
    local lo = HEX_VAL[h:byte(i + 1)]
    if not (hi and lo) then
      return nil, "hex_invalid_chars"
    end
    out[j] = string.char(hi * 16 + lo)
    j = j + 1
    i = i + 2
  end
  local decoded = table.concat(out)
  if n <= CACHE_MAX_INPUT then
    if _hex_dec_n >= CACHE_MAX_ENTRIES then
      _hex_dec_cache = { }
      _hex_dec_n = 0
    end
    _hex_dec_cache[h] = decoded
    _hex_dec_n = _hex_dec_n + 1
  end
  return decoded, nil
end
local split_fields
split_fields = function(line)
  local out = { }
  local i = 1
  while true do
    local j = line:find("|", i, true)
    if j then
      out[#out + 1] = line:sub(i, j - 1)
      i = j + 1
    else
      out[#out + 1] = line:sub(i)
      break
    end
  end
  return out
end
local BYTE_0, BYTE_9 = 48, 57
local BYTE_DOT, BYTE_COLON = 46, 58
local is_digit
is_digit = function(b)
  return b >= BYTE_0 and b <= BYTE_9
end
local is_ipv4_str
is_ipv4_str = function(s)
  if not (s and #s > 0) then
    return false
  end
  local groups = 1
  local digits = 0
  local i = 1
  local n = #s
  while i <= n do
    local b = s:byte(i)
    if b == BYTE_DOT then
      if digits == 0 or groups >= 4 then
        return false
      end
      groups = groups + 1
      digits = 0
    elseif is_digit(b) then
      digits = digits + 1
    else
      return false
    end
    i = i + 1
  end
  return groups == 4 and digits > 0
end
local is_ipv6_str
is_ipv6_str = function(s)
  return s and s:find(":", 1, true)
end
local is_valid_mac
is_valid_mac = function(s)
  if not (type(s) == "string" and #s == 17) then
    return false
  end
  for i = 1, 17 do
    local b = s:byte(i)
    if i % 3 == 0 then
      if not (b == BYTE_COLON) then
        return false
      end
    else
      if not (HEX_VAL[b]) then
        return false
      end
    end
  end
  return true
end
local is_timeout_unit
is_timeout_unit = function(b)
  return b == 115 or b == 109 or b == 104 or b == 100 or b == 119
end
local is_valid_timeout
is_valid_timeout = function(t)
  if not (type(t) == "string") then
    return false
  end
  local n = #t
  if not (n > 0 and n <= 16) then
    return false
  end
  local i = 1
  while i <= n do
    if not (is_digit(t:byte(i))) then
      break
    end
    i = i + 1
  end
  if i == 1 then
    return false
  end
  if i > n then
    return true
  end
  if i < n then
    return false
  end
  return is_timeout_unit(t:byte(i))
end
return {
  encode_ip16 = encode_ip16,
  to_hex = to_hex,
  from_hex = from_hex,
  split_fields = split_fields,
  is_valid_timeout = is_valid_timeout,
  is_ipv4_str = is_ipv4_str,
  is_ipv6_str = is_ipv6_str,
  is_valid_mac = is_valid_mac,
  is_digit = is_digit,
  is_timeout_unit = is_timeout_unit
}
