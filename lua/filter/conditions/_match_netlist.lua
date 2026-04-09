return function(prop)
  return function(cfg)
    return function(name)
      local _match_net = require("filter.conditions._match_net")(prop)(cfg)
      local nets = cfg.nets or { }
      return function(req)
        local netlist = nets[name]
        if not (netlist) then
          return false, "Net list '" .. tostring(name) .. "' not defined"
        end
        for _index_0 = 1, #netlist do
          local cidr = netlist[_index_0]
          local ok = _match_net(cidr)(req)
          if ok then
            return true, tostring(req[prop]) .. " in netlist '" .. tostring(name) .. "'"
          end
        end
        return false, "Not in netlist '" .. tostring(name) .. "'"
      end
    end
  end
end
