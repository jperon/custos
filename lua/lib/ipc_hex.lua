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
local to_hex
to_hex = function(s)
  if not (s and #s > 0) then
    return ""
  end
  return (s:gsub(".", function(c)
    return string.format("%02x", c:byte())
  end))
end
local from_hex
from_hex = function(h)
  if not h or #h == 0 then
    return "", nil
  end
  if (#h % 2) ~= 0 then
    return nil, "hex_odd_length"
  end
  if not (h:match("^[0-9a-fA-F]+$")) then
    return nil, "hex_invalid_chars"
  end
  local out = { }
  for i = 1, #h, 2 do
    out[#out + 1] = string.char(tonumber(h:sub(i, i + 1), 16))
  end
  return table.concat(out), nil
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
local is_ipv4_str
is_ipv4_str = function(s)
  return s and s:match("^%d+%.%d+%.%d+%.%d+$")
end
local is_ipv6_str
is_ipv6_str = function(s)
  return s and s:find(":", 1, true)
end
local is_valid_mac
is_valid_mac = function(s)
  return s and s:match("^[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]:[%x][%x]$")
end
local is_valid_timeout
is_valid_timeout = function(t)
  if not (type(t) == "string") then
    return false
  end
  if not (#t > 0 and #t <= 16) then
    return false
  end
  return t:match("^%d+[smhdw]?$") ~= nil
end
return {
  encode_ip16 = encode_ip16,
  to_hex = to_hex,
  from_hex = from_hex,
  split_fields = split_fields,
  is_valid_timeout = is_valid_timeout,
  is_ipv4_str = is_ipv4_str,
  is_ipv6_str = is_ipv6_str,
  is_valid_mac = is_valid_mac
}
