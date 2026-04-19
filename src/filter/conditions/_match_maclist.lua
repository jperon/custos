return function(prop)
  return function(cfg)
    return function(name)
      local _match_mac = require("filter.conditions._match_mac")(prop)(cfg)
      local maclists = cfg.maclists or { }
      return function(req)
        local maclist = maclists[name]
        if not (maclist) then
          return false, "MAC list '" .. tostring(name) .. "' not defined"
        end
        for _index_0 = 1, #maclist do
          local item = maclist[_index_0]
          local ok = _match_mac(item)(req)
          if ok then
            return true, tostring(req[prop]) .. " in maclist '" .. tostring(name) .. "'"
          end
        end
        return false, "Not in maclist '" .. tostring(name) .. "'"
      end
    end
  end
end
