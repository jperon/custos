return function(cfg)
  return function(list_name)
    local time_lists = cfg.times_lists or { }
    local window_names = time_lists[list_name]
    if not (window_names) then
      return function(req)
        return false, "Time list '" .. tostring(list_name) .. "' not defined"
      end
    end
    local in_time_factory = require("filter.conditions.in_time")
    local windows = { }
    for _, name in ipairs(window_names) do
      windows[#windows + 1] = in_time_factory(cfg(name))
    end
    return function(req)
      for _, window_fn in ipairs(windows) do
        local ok, reason = window_fn(req)
        if ok then
          return true, reason
        end
      end
      return false, "Outside all windows in list '" .. tostring(list_name) .. "'"
    end
  end
end
