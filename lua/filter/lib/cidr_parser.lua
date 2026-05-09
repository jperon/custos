local bit = require("bit")
local parse_ipv4_cidr
parse_ipv4_cidr = function(cidr_str)
  if not (cidr_str) then
    return nil
  end
  local s = tostring(cidr_str):match("^%s*(.-)%s*$")
  if not (s and #s > 0) then
    return nil
  end
  if s:find(":") then
    return nil
  end
  local addr_part, prefix_part = s:match("^([^/]+)/?(.*)$")
  if not (addr_part) then
    return nil
  end
  local prefix = tonumber(prefix_part)
  if not (prefix_part and #prefix_part > 0) then
    prefix = 32
  end
  if not (prefix >= 0 and prefix <= 32) then
    return nil
  end
  local parts = { }
  for p in addr_part:gmatch("[0-9]+") do
    parts[#parts + 1] = tonumber(p)
  end
  if not (#parts == 4) then
    return nil
  end
  for _index_0 = 1, #parts do
    local p = parts[_index_0]
    if not (p >= 0 and p <= 255) then
      return nil
    end
  end
  return {
    cidr = s,
    net = addr_part,
    prefix = prefix,
    family = "inet",
    is_valid = true
  }
end
local parse_ipv6_cidr
parse_ipv6_cidr = function(cidr_str)
  if not (cidr_str) then
    return nil
  end
  local s = tostring(cidr_str):match("^%s*(.-)%s*$")
  if not (s and #s > 0) then
    return nil
  end
  if not (s:find(":")) then
    return nil
  end
  local addr_part, prefix_part = s:match("^([^/]+)/?(.*)$")
  if not (addr_part) then
    return nil
  end
  local prefix = tonumber(prefix_part)
  if not (prefix_part and #prefix_part > 0) then
    prefix = 128
  end
  if not (prefix >= 0 and prefix <= 128) then
    return nil
  end
  if not (addr_part:find(":")) then
    return nil
  end
  return {
    cidr = s,
    net = addr_part,
    prefix = prefix,
    family = "inet6",
    is_valid = true
  }
end
local parse_cidr
parse_cidr = function(cidr_str)
  if not (cidr_str) then
    return nil
  end
  local s = tostring(cidr_str)
  if s:find(":", 1, true) then
    return parse_ipv6_cidr(s)
  else
    return parse_ipv4_cidr(s)
  end
end
local validate_cidr
validate_cidr = function(cidr_str)
  local parsed = parse_cidr(cidr_str)
  if not (parsed) then
    return false, "Invalid CIDR notation: " .. tostring(cidr_str)
  end
  return true, nil
end
local format_cidr
format_cidr = function(parsed)
  if not (parsed) then
    return nil
  end
  if not (parsed.net and parsed.prefix) then
    return nil
  end
  if parsed.family == "inet6" then
    return tostring(parsed.net) .. "/" .. tostring(parsed.prefix)
  else
    return tostring(parsed.net) .. "/" .. tostring(parsed.prefix)
  end
end
return {
  parse_cidr = parse_cidr,
  parse_ipv4_cidr = parse_ipv4_cidr,
  parse_ipv6_cidr = parse_ipv6_cidr,
  validate_cidr = validate_cidr,
  format_cidr = format_cidr
}
