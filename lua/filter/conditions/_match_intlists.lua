return function(prop)
  return function(cfg)
    return function(list_names)
      if not (type(list_names == "table")) then
        error("list_names must be a table of list names")
      end
      local _match_intlist = require("filter.conditions._match_intlist")
      local match_fn = _match_intlist(prop(cfg))
      return function(req)
        for _, name in ipairs(list_names) do
          local ok, reason = _match_intlist(name(req))
          if ok then
            return true, reason
          end
        end
        return false, tostring(prop) .. " not in any of the specified lists"
      end
    end
  end
end
