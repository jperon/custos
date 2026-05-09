return function(cfg)
  return function(subnet_spec)
    if not (subnet_spec) then
      return function(req)
        return false, "from_subnet requires a subnet specification"
      end
    end
    local net_cidr = nil
    if type(subnet_spec) == "string" then
      net_cidr = subnet_spec
    elseif type(subnet_spec) == "table" and subnet_spec.net then
      net_cidr = subnet_spec.net
    end
    if not (net_cidr) then
      return function(req)
        return false, "Invalid subnet specification"
      end
    end
    local Net
    Net = require("filter.lib.ipcalc").Net
    local _net = Net(net_cidr)
    if _net then
      return function(req)
        local ip = req.src_ip
        if not (ip) then
          return false, "Missing src_ip"
        end
        if _net:contains(ip) then
          return true, tostring(ip) .. " in subnet " .. tostring(net_cidr)
        else
          return false, tostring(ip) .. " not in subnet " .. tostring(net_cidr)
        end
      end
    else
      return function(req)
        return false, "Invalid CIDR: " .. tostring(net_cidr)
      end
    end
  end
end
