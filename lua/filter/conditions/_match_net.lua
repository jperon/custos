return function(prop)
  return function(cfg)
    return function(net_cidr)
      if net_cidr == "_any" then
        return function(req)
          local ip = req[prop]
          return ip ~= nil, tostring(prop) .. " present"
        end
      end
      if net_cidr == "_none" then
        return function(req)
          local ip = req[prop]
          return ip == nil, tostring(prop) .. " absent"
        end
      end
      local Net
      Net = require("filter.lib.ipcalc").Net
      local _net = Net(net_cidr)
      if _net then
        return function(req)
          local ip = req[prop]
          if not (ip) then
            return false, "Missing " .. tostring(prop)
          end
          if _net:contains(ip) then
            return true, tostring(ip) .. " in " .. tostring(net_cidr)
          else
            return false, tostring(ip) .. " not in " .. tostring(net_cidr)
          end
        end
      else
        return function(req)
          return false, "Invalid CIDR: " .. tostring(net_cidr)
        end
      end
    end
  end
end
