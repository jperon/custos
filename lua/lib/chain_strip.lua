local chain_strip_active
chain_strip_active = function(config)
  local rules = config and config.filter and config.filter.rules
  if not (type(rules) == "table") then
    return false
  end
  local compiler_api = require("filter.compiler_api")
  for _index_0 = 1, #rules do
    local r = rules[_index_0]
    local strip_cfg = r.dns_strip
    local _list_0 = (r.actions or { })
    for _index_1 = 1, #_list_0 do
      local entry = _list_0[_index_1]
      if compiler_api.action_name_of(entry) == "dns_strip" then
        local opts = compiler_api.action_options_of(entry)
        if opts then
          strip_cfg = opts
        end
      end
    end
    if strip_cfg and strip_cfg.follow_cname ~= false then
      return true
    end
  end
  return false
end
return {
  chain_strip_active = chain_strip_active
}
