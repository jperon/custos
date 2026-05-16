return function(cfg)
  return function(subnet_spec)
    if not (subnet_spec) then
      return {
        capabilities = {
          worker = true,
          nft_static = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "from_subnet requires a subnet specification"
        end
      }
    end
    local net_cidr = nil
    if type(subnet_spec) == "string" then
      net_cidr = subnet_spec
    elseif type(subnet_spec) == "table" and subnet_spec.net then
      net_cidr = subnet_spec.net
    end
    if not (net_cidr) then
      return {
        capabilities = {
          worker = true,
          nft_static = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "Invalid subnet specification"
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
          return true, tostring(ip) .. " in subnet " .. tostring(net_cidr)
        else
          return false, tostring(ip) .. " not in subnet " .. tostring(net_cidr)
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
