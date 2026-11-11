local tsv_field
tsv_field = function(v)
  local s
  if v ~= nil then
    s = tostring(v)
  else
    s = ""
  end
  if #s == 0 then
    return "-"
  else
    return s
  end
end
return {
  tsv_field = tsv_field
}
