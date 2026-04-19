return function(cfg)
  return function(list_names)
    if not (type(list_names == "table")) then
      error("in_timelists requires a table of list names")
    end
    local in_timelist_factory = require("filter.conditions.in_timelist")
    local list_fns = { }
    for _, name in ipairs(list_names) do
      list_fns[#list_fns + 1] = in_timelist_factory(cfg(name))
    end
    return function(req)
      for _, list_fn in ipairs(list_fns) do
        local ok, reason = list_fn(req)
        if ok then
          return true, reason
        end
      end
      return false, "Outside all windows in specified lists"
    end
  end
end
