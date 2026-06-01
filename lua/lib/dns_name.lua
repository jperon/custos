local encode_dns_name
encode_dns_name = function(name)
  name = name:gsub("%.+$", "")
  local parts = { }
  for label in name:gmatch("[^.]+") do
    parts[#parts + 1] = string.char(#label) .. label
  end
  return table.concat(parts) .. "\x00"
end
return {
  encode_dns_name = encode_dns_name
}
