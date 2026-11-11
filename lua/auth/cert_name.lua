local MAX_HOSTNAME_LEN = 253
local MAX_LABEL_LEN = 63
local is_ipv4_literal
is_ipv4_literal = function(name)
  return name:match("^%d+%.%d+%.%d+%.%d+$") ~= nil
end
local sanitize_hostname
sanitize_hostname = function(hostname)
  if not (type(hostname) == "string") then
    return nil
  end
  local name = hostname:lower()
  if #name == 0 or #name > MAX_HOSTNAME_LEN then
    return nil
  end
  if name:find("[^a-z0-9.%-]") then
    return nil
  end
  if name:find("%.%.") or name:sub(1, 1) == "." or name:sub(-1) == "." then
    return nil
  end
  if is_ipv4_literal(name) then
    return nil
  end
  for label in name:gmatch("[^.]+") do
    if #label > MAX_LABEL_LEN then
      return nil
    end
    if label:sub(1, 1) == "-" or label:sub(-1) == "-" then
      return nil
    end
  end
  return name
end
local safe_cert_name
safe_cert_name = function(name)
  if not (type(name) == "string") then
    return nil
  end
  local lname = name:lower()
  if #lname == 0 or #lname > MAX_HOSTNAME_LEN then
    return nil
  end
  if lname:find("[^a-z0-9.%-:]") then
    return nil
  end
  if lname:find("%.%.") or lname:sub(1, 1) == "." or lname:sub(-1) == "." then
    return nil
  end
  return lname
end
return {
  sanitize_hostname = sanitize_hostname,
  safe_cert_name = safe_cert_name,
  is_ipv4_literal = is_ipv4_literal,
  MAX_HOSTNAME_LEN = MAX_HOSTNAME_LEN,
  MAX_LABEL_LEN = MAX_LABEL_LEN
}
