local chain_strip_active
chain_strip_active = function(config)
  local rules = config and config.filter and config.filter.rules
  if not (type(rules) == "table") then
    return false
  end
  for _index_0 = 1, #rules do
    local r = rules[_index_0]
    if r.dns_strip and r.dns_strip.follow_cname then
      return true
    end
  end
  return false
end
return {
  chain_strip_active = chain_strip_active
}
