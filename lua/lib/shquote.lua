local shquote
shquote = function(s)
  s = tostring(s)
  return "'" .. (s:gsub("'", "'\\''")) .. "'"
end
return {
  shquote = shquote
}
