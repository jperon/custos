local is_valid
is_valid = function(s)
  if #s == 0 or #s > 253 then
    return false
  end
  if s:match("^%d+%.%d+%.%d+%.%d+$") then
    return false
  end
  if s:match(":") then
    return false
  end
  if not (s:match("%.")) then
    return false
  end
  if not (s:match("^[a-z0-9][a-z0-9._%-]*[a-z0-9]$")) then
    return false
  end
  return true
end
local parse_simple
parse_simple = function(text)
  local result = { }
  for line in text:gmatch("[^\n]+") do
    local _continue_0 = false
    repeat
      local domain = line:match("^%s*([^%s#]+)")
      if not (domain) then
        _continue_0 = true
        break
      end
      domain = domain:lower()
      if is_valid(domain) then
        result[#result + 1] = domain
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return result
end
local parse_hosts
parse_hosts = function(text)
  local skip = {
    localhost = true,
    broadcasthost = true,
    ["0.0.0.0"] = true,
    ["::1"] = true,
    ["127.0.0.1"] = true
  }
  local result = { }
  for line in text:gmatch("[^\n]+") do
    local _continue_0 = false
    repeat
      line = line:match("^%s*(.-)%s*$")
      if line == "" or line:sub(1, 1) == "#" then
        _continue_0 = true
        break
      end
      local _, domain = line:match("^(%S+)%s+(%S+)")
      if not (domain) then
        _continue_0 = true
        break
      end
      domain = domain:lower()
      if skip[domain] then
        _continue_0 = true
        break
      end
      if is_valid(domain) then
        result[#result + 1] = domain
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return result
end
local parse_adblock
parse_adblock = function(text)
  local result = { }
  for line in text:gmatch("[^\n]+") do
    local _continue_0 = false
    repeat
      local domain = line:match("^||([^%^/|@%s]+)%^")
      if not (domain) then
        _continue_0 = true
        break
      end
      domain = domain:lower()
      if is_valid(domain) then
        result[#result + 1] = domain
      end
      _continue_0 = true
    until true
    if not _continue_0 then
      break
    end
  end
  return result
end
local parsers = {
  simple = parse_simple,
  hosts = parse_hosts,
  adblock = parse_adblock
}
local parse
parse = function(format, text)
  local fn = parsers[format] or parse_simple
  return fn(text)
end
return {
  parse = parse,
  parse_simple = parse_simple,
  parse_hosts = parse_hosts,
  parse_adblock = parse_adblock,
  is_valid = is_valid
}
