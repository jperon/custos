return function(cfg)
  return function(net_cidr)
    if net_cidr == "_any" then
      return {
        capabilities = {
          worker = true,
          nft_static = false,
          nft_dynamic = false
        },
        net_cidr = net_cidr,
        eval = function(req)
          local ip = req.src_ip
          return ip ~= nil, "src_ip present"
        end
      }
    end
    if net_cidr == "_none" then
      return {
        capabilities = {
          worker = true,
          nft_static = false,
          nft_dynamic = false
        },
        net_cidr = net_cidr,
        eval = function(req)
          local ip = req.src_ip
          return ip == nil, "src_ip absent"
        end
      }
    end
    local Net
    Net = require("filter.lib.ipcalc").Net
    local _net = Net(net_cidr)
    if not (_net) then
      return {
        capabilities = {
          worker = true,
          nft_static = false,
          nft_dynamic = false
        },
        net_cidr = net_cidr,
        eval = function(req)
          return false, "Invalid CIDR: " .. tostring(net_cidr)
        end
      }
    end
    return {
      capabilities = {
        worker = true,
        nft_static = true,
        nft_dynamic = false
      },
      net_cidr = net_cidr,
      _net = _net,
      eval = function(req)
        local ip = req.src_ip
        if not (ip) then
          return false, "Missing src_ip"
        end
        if _net:contains(ip) then
          return true, tostring(ip) .. " in " .. tostring(net_cidr)
        else
          return false, tostring(ip) .. " not in " .. tostring(net_cidr)
        end
      end,
      compile_nft = function(family)
        if net_cidr:find(":") then
          if family == "inet6" or family == "ip6" then
            return "ip6 saddr " .. tostring(net_cidr), nil
          end
          return nil, "IPv6 CIDR in IPv4 family"
        else
          if family == "inet" or family == "ip" then
            return "ip saddr " .. tostring(net_cidr), nil
          end
          return nil, "IPv4 CIDR in IPv6 family"
        end
      end
    }
  end
end
