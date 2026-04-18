return function(prop)
  return function(cfg)
    return function(name)
      local _match_mac = require("filter.conditions._match_mac")(prop)(cfg)
      local macs = cfg.macs or { }
      return function(req)
        local maclist = macs[name]
        if not (maclist) then
          return false, "MAC list '" .. tostring(name) .. "' not defined"
        end
        for _index_0 = 1, #maclist do
          local mac = maclist[_index_0]
          local ok = _match_mac(mac)(req)
          if ok then
            return true, tostring(req[prop]) .. " in maclist '" .. tostring(name) .. "'"
          end
        end
        return false, "Not in maclist '" .. tostring(name) .. "'"
      end
    end
  end
end
