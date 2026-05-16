return function(cfg)
  return function(cidrs)
    if not (type(cidrs) == "table") then
      return {
        capabilities = {
          worker = true,
          nft = false,
          nft_dynamic = false
        },
        eval = function(req)
          return false, "to_nets requires a table of CIDRs"
        end
      }
    end
    local Net
    Net = require("filter.lib.ipcalc").Net
    local nets = { }
    for _, cidr in ipairs(cidrs) do
      local net = Net(cidr)
      if net then
        nets[#nets + 1] = {
          net = net,
          cidr = cidr
        }
      end
    end
    return {
      capabilities = {
        worker = true,
        nft = true,
        nft_dynamic = false
      },
      cidrs = cidrs,
      eval = function(req)
        local ip = req.dst_ip
        if not (ip) then
          return false, "dst_ip not available"
        end
        for _, entry in ipairs(nets) do
          if entry.net:contains(ip) then
            return true, tostring(ip) .. " in " .. tostring(entry.cidr)
          end
        end
        return false, tostring(ip) .. " not in any CIDR"
      end,
      compile_nft = function(family)
        local cidr_str = table.concat(cidrs, ", ")
        local is_ipv6 = cidrs[1] and cidrs[1]:find(":")
        if is_ipv6 then
          return "ip6 daddr { " .. tostring(cidr_str) .. " }", nil
        else
          return "ip daddr { " .. tostring(cidr_str) .. " }", nil
        end
      end
    }
  end
end
